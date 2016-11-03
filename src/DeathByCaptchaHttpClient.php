<?php
/**
 * @Author: Phu Hoang
 * @Date:   2015-11-09 16:09:25
 * @Last Modified by:   Phu Hoang
 * @Last Modified time: 2015-11-09 18:08:05
 */

namespace hmphu\deathbycaptcha;

/**
 * Death by Captcha HTTP API Client
 *
 * @see DeathByCaptchaClient
 * @package DBCAPI
 * @subpackage PHP
 */
class DeathByCaptchaHttpClient extends DeathByCaptchaClient
{
    const BASE_URL = 'http://api.dbcapi.me/api';


    protected $_conn = null;
    protected $_response_type = '';
    protected $_response_parser = null;


    /**
     * Sets up CURL connection
     */
    protected function _connect()
    {
        if (!is_resource($this->_conn)) {
            if ($this->is_verbose) {
                fputs(STDERR, time() . " CONN\n");
            }

            if (!($this->_conn = curl_init())) {
                throw new DeathByCaptchaRuntimeException(
                    'Failed initializing a CURL connection'
                );
            }

            curl_setopt_array($this->_conn, array(
                CURLOPT_TIMEOUT => self::DEFAULT_TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => (int)(self::DEFAULT_TIMEOUT / 4),
                CURLOPT_HEADER => false,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_VERBOSE => true,
				CURLINFO_HEADER_OUT  => true,
                CURLOPT_AUTOREFERER => false,
                CURLOPT_HTTPHEADER => array(
                    'Accept: ' . $this->_response_type,
                    'Expect: ',
                    'User-Agent: ' . self::API_VERSION
                )
            ));
        }

        return $this;
    }
    
    protected function getCurlCommand(){
    	$command = "curl ";
    	$params = array(
    		["--max-time" , self::DEFAULT_TIMEOUT],
    		["--connect-timeout" , (int)(self::DEFAULT_TIMEOUT / 4)],
    		["--user-agent" , self::API_VERSION],
			["--location" , ""],
			["--silent" , ""],
			["--write-out" , '\n%{response_code}'],
			["--header" , "Expect: "],
			["--header" , "Accept: $this->_response_type"],
		);
    	foreach ($params as $param){
    		$command.= " $param[0] " . ( mb_strlen( (string) $param[1] ) > 0 ? "'$param[1]'" : "" );
		}
		return $command;
	}

    /**
     * Makes an API call
     *
     * @param string $cmd     API command
     * @param array  $payload API call payload, essentially HTTP POST fields
     * @return array|null API response hash table on success
     * @throws DeathByCaptchaIOException On network related errors
     * @throws DeathByCaptchaAccessDeniedException On failed login attempt
     * @throws DeathByCaptchaInvalidCaptchaException On invalid CAPTCHAs rejected by the service
     * @throws DeathByCaptchaServerException On API server errors
     */
    protected function _call($cmd, $payload=null)
    {
        if (null !== $payload) {
            $payload = array_merge($payload, array(
                'username' => $this->_userpwd[0],
                'password' => $this->_userpwd[1],
            ));
        }

        $command = $this->getCurlCommand();
	
		$url = self::BASE_URL . '/' . trim($cmd, '/');
		foreach($payload as $key => $element){
			$command .= " --form $key='$element' ";
		}
	
		$command .= " $url ";
		xdebug_var_dump($command);
		$res = exec($command, $output, $var);
		if (0 < $var) {
			throw new DeathByCaptchaIOException(
				"API connection failed: [{$var}] " . implode(',', $output)
			);
		}
	
		$status_code = (int) $res;
		$format_output = implode('',array_slice($output, 0, -1));
		$parser = $this->_response_parser;
	
		if (403 == $status_code) {
			throw new DeathByCaptchaAccessDeniedException(
				'Access denied, check your credentials and/or balance'
			);
		} else if (400 == $status_code || 413 == $status_code) {
			throw new DeathByCaptchaInvalidCaptchaException(
				"CAPTCHA was rejected by the service, check if it's a valid image"
			);
		} else if (503 == $status_code) {
			throw new DeathByCaptchaServiceOverloadException(
				"CAPTCHA was rejected due to service overload, try again later"
			);
//		} else if (!($output = self::parse_plain_response($format_output))) {
		} else if ( !( $output = call_user_func($parser, $format_output) )) {
			throw new DeathByCaptchaServerException(
				'Invalid API response'
			);
		} else {
			return $output;
		}
    }


    /**
     * @see DeathByCaptchaClient::__construct()
     */
    public function __construct($username, $password)
    {
        if (!extension_loaded('curl')) {
            throw new DeathByCaptchaRuntimeException(
                'CURL extension not found'
            );
        }
        if (function_exists('json_decode')) {
            $this->_response_type = 'application/json';
            $this->_response_parser = array($this, 'parse_json_response');
        } else {
            $this->_response_type = 'text/plain';
            $this->_response_parser = array($this, 'parse_plain_response');
        }
        parent::__construct($username, $password);
    }

    /**
     * @see DeathByCaptchaClient::close()
     */
    public function close()
    {
        if (is_resource($this->_conn)) {
            if ($this->is_verbose) {
                fputs(STDERR, time() . " CLOSE\n");
            }
            curl_close($this->_conn);
            $this->_conn = null;
        }
        return $this;
    }

    /**
     * @see DeathByCaptchaClient::get_user()
     */
    public function get_user()
    {
        $user = $this->_call('user', array());
        return (0 < ($id = (int)@$user['user']))
            ? array('user' => $id,
                    'balance' => (float)@$user['balance'],
                    'is_banned' => (bool)@$user['is_banned'])
            : null;
    }

    /**
     * @see DeathByCaptchaClient::upload()
     * @throws DeathByCaptchaRuntimeException When failed to save CAPTCHA image to a temporary file
     */
    public function upload($captcha)
    {
        $img = $this->_load_captcha($captcha);
        if ($this->_is_valid_captcha($img)) {
            $tmp_fn = tempnam(null, 'captcha');
            file_put_contents($tmp_fn, $img);
            try {
                $captcha = $this->_call('captcha', array(
                    'captchafile' => '@'. $tmp_fn,
                ));
            } catch (\Exception $e) {
                @unlink($tmp_fn);
                throw $e;
            }
            if (0 < ($cid = (int)@$captcha['captcha']) ) {
                return array(
                    'captcha' => $cid,
                    'text' => (!empty($captcha['text']) ? $captcha['text'] : null),
                    'is_correct' => (bool)@$captcha['is_correct'],
                );
            }
        }
        return null;
    }

    /**
     * @see DeathByCaptchaClient::get_captcha()
     */
    public function get_captcha($cid)
    {
        $captcha = $this->_call('captcha/' . (int)$cid);
        return (0 < ($cid = (int)@$captcha['captcha']))
            ? array('captcha' => $cid,
                    'text' => (!empty($captcha['text']) ? $captcha['text'] : null),
                    'is_correct' => (bool)$captcha['is_correct'])
            : null;
    }

    /**
     * @see DeathByCaptchaClient::report()
     */
    public function report($cid)
    {
        $captcha = $this->_call('captcha/' . (int)$cid . '/report', array());
        return !(bool)@$captcha['is_correct'];
    }
}