<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class CI_Session_files_driver extends CI_Session_driver implements SessionHandlerInterface {
    protected $_save_path;
    protected $_file_handle;
    protected $_file_path;
    protected $_file_new;
    protected $_sid_regexp;
    protected static $func_overload;

    public function __construct(&$params)
    {
        parent::__construct($params);
        if (isset($this->_config['save_path'])) {
            $this->_config['save_path'] = rtrim($this->_config['save_path'], '/\\');
            ini_set('session.save_path', $this->_config['save_path']);
        } else {
            log_message('debug', 'Session: "sess_save_path" is empty; using "session.save_path" value from php.ini.');
            $this->_config['save_path'] = rtrim(ini_get('session.save_path'), '/\\');
        }

        $this->_sid_regexp = $this->_config['_sid_regexp'];
        isset(self::$func_overload) OR self::$func_overload = (extension_loaded('mbstring') && ini_get('mbstring.func_overload'));
    }

    public function open($save_path, $name): bool
    {
        if (!is_dir($save_path)) {
            if (!mkdir($save_path, 0700, true)) {
                throw new Exception("Session: Configured save path '".$this->_config['save_path']."' is not a directory, doesn't exist or cannot be created.");
            }
        } elseif (!is_writable($save_path)) {
            throw new Exception("Session: Configured save path '".$this->_config['save_path']."' is not writable by the PHP process.");
        }

        $this->_config['save_path'] = $save_path;
        $this->_file_path = $this->_config['save_path'].DIRECTORY_SEPARATOR
            .$name
            .($this->_config['match_ip'] ? md5($_SERVER['REMOTE_ADDR']) : '');

        $this->php5_validate_id();
        return true;
    }

    public function read($session_id): string
    {
        if ($this->_file_handle === NULL) {
            $this->_file_new = !file_exists($this->_file_path.$session_id);

            if (($this->_file_handle = fopen($this->_file_path.$session_id, 'c+b')) === FALSE) {
                log_message('error', "Session: Unable to open file '".$this->_file_path.$session_id."'.");
                return '';
            }

            if (flock($this->_file_handle, LOCK_EX) === FALSE) {
                log_message('error', "Session: Unable to obtain lock for file '".$this->_file_path.$session_id."'.");
                fclose($this->_file_handle);
                $this->_file_handle = NULL;
                return '';
            }

            $this->_session_id = $session_id;

            if ($this->_file_new) {
                chmod($this->_file_path.$session_id, 0600);
                return '';
            }
        } elseif ($this->_file_handle === FALSE) {
            return '';
        } else {
            rewind($this->_file_handle);
        }

        $session_data = '';
        while (($buffer = fread($this->_file_handle, 8192)) !== false) {
            $session_data .= $buffer;
        }

        return $session_data;
    }

    public function write($session_id, $session_data): bool
    {
        if ($session_id !== $this->_session_id && ($this->close() === false || $this->read($session_id) === false)) {
            return false;
        }

        if (!is_resource($this->_file_handle)) {
            return false;
        } elseif ($this->_fingerprint === md5($session_data)) {
            return true;
        }

        if (!$this->_file_new) {
            ftruncate($this->_file_handle, 0);
            rewind($this->_file_handle);
        }

        if (($length = strlen($session_data)) > 0) {
            fwrite($this->_file_handle, $session_data);
        }

        $this->_fingerprint = md5($session_data);
        return true;
    }

    public function close(): bool
    {
        if (is_resource($this->_file_handle)) {
            flock($this->_file_handle, LOCK_UN);
            fclose($this->_file_handle);
            $this->_file_handle = NULL;
        }
        return true;
    }

    public function destroy($session_id): bool
    {
        if ($this->close() === true) {
            return unlink($this->_file_path.$session_id) ? true : false;
        }
        return false;
    }

    public function gc($maxlifetime): int|false
    {
        if (!is_dir($this->_config['save_path']) || ($directory = opendir($this->_config['save_path']) === false)) {
            log_message('debug', "Session: Garbage collector couldn't list files under directory '".$this->_config['save_path']."'.");
            return false;
        }

        $ts = time() - $maxlifetime;
        $deleted_files = 0;

        $pattern = sprintf(
            '#\A%s[0-9a-f]{32}'.$this->_sid_regexp.'\z#',
            preg_quote($this->_config['cookie_name'])
        );

        while (($file = readdir($directory)) !== false) {
            if (!preg_match($pattern, $file)
                || !is_file($this->_config['save_path'].DIRECTORY_SEPARATOR.$file)
                || ($mtime = filemtime($this->_config['save_path'].DIRECTORY_SEPARATOR.$file)) === false
                || $mtime > $ts) {
                continue;
            }
            unlink($this->_config['save_path'].DIRECTORY_SEPARATOR.$file);
            $deleted_files++;
        }

        closedir($directory);
        return $deleted_files;
    }

    public function validateSessionId($id): bool
    {
        return is_file($this->_file_path.$id);
    }

    protected static function strlen($str): int
    {
        return (self::$func_overload)
            ? mb_strlen($str, '8bit')
            : strlen($str);
    }
}
