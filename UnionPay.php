<?php
namespace Unionpay;
require_once('vendor/autoload.php');
use \Monolog\Logger as Logger;
use \Monolog\Handler\StreamHandler as StreamHandler;
use \Dotenv\Dotenv as Dotenv;
/**
* author @jude@ipayafrica.com
* date: 12/11/2019
* The unionpay class is specific to Union Pay credit cards. The class receives a request in json format. 
* A determination is made as to the payment type. Validations are carried out. Data is encrypted using
* private and public keys and forwarded to the payment processor. On receipt of response. The public key and
* signature are validated. A successful response means that the request was successful. The payment types
* include purchase, purchase cancellation, preauthorization , preauthorization complete, preauthorization
* complete cancel and refund 
*
*
**/
class UnionPay{
	/* transaction Types*/
	const PURCHASE = 1;
	const CANCELPURCHASE  = 2;
	const REFUND  = 3;
	const PREAUTH = 4;
	const CANCELPREAUTH=5;
	const COMPLETEPREAUTH=6;
	const CANCELCOMPLETEPREAUTH=7;
	const RECURRING=8;
	const QUERY=9;
	/* variables required unionpay request creation*/
	
	private $version;
	private $encoding;
	private $signMethod;
	private $txntype;
	private $txnSubType;
	private $bizType;
	private $accessType;
	private $channelType;
	private $currencyCode;
	private $merId;

	/** backUrl callback url that receives server to server response */
	private $backUrl;
	/** frontUrl is a callback url that is a server to client response */
	private $frontUrl;
	/*identifier of certificate used for encryption of data */
    private $certId;

    //public $frontTransUrl;


	/*to store the basic required items when making a request */
	private $orderId;
	private $txnTime;
	private $txnAmt;

	public $log;

	/** Encryption public key and certificate for sensitive information */
	private $encryptCert = null;

	
	
	 /** Path of signed certificate. */
    protected $signCertPath;
    /** Password of signed certificate. */
    protected $signCertPwd;
    /** Type of signed certificate. */
    protected $signCertType;
    /** Path of encrypted public key certificate. */
    //public $encryptCertPath;
    /** Authenticate the catalog of signed public key certificates. */
    protected $validateCertDir;
    /** Read the catalog of specified signed certificates according to client codes. */
    protected $signCertDir;
    /** Security key (used in calculation of SHA256 and SM3) */
    protected $secureKey;
	/** algorithm for signing data**/
	protected $alg;
    
	private static $keystore = null;
	/** Encryption public key for magnetic tracks */
	private static $encryptTrackKey = null;
	/** Verify the messages, signatures, and certificates returned from China UnionPay. */
	private static $validateCert = null;
	/** Authenticate the signatures of intermediate certificates */
	private static $middleCert = null;
	/** Authenticate the signatures of root certificates */
	private static $rootCert = null;
    
	private static $instance;

	private $frontRequestUrl;


	/** Path of intermediate certificates  */
	private $middleCertPath;
	/** Path of root certificates  */
	private $rootCertPath;
	/** For whether to verify the CNs of the certificates for verifying certificates, all certificates except the ones for which this parameter has been set to false should be authenticated.  */
	private $ifValidateCNName = true;
	/** For whether to authenticate the https certificate, all certificates need not to be authenticated by default.  */
	private $ifValidateRemoteCert = false;
	/*url used to make request to unionpay server*/
	public $backTransUrl;

	public function __construct(){
	/*
		set default values during class instantiation
	*/
		//$this->getLogFile("upop");
		$this->version=getenv('UPOP.VERSION');
		$this->encoding=getenv('UPOP.ENCODING');
		$this->signMethod=getenv('UPOP.SIGNMETHOD');
		$this->bizType=getenv('UPOP.BIZTYPE');
		$this->accessType=getenv('UPOP.ACCESSTYPE');
		$this->channelType=getenv('UPOP.CHANNELTYPE');
		$this->merId=getenv('UPOP.MERCHANTID');
		$this->currencyCode=getenv('UPOP.CURRENCYCODE');
		//$this->payTimeOut=getenv('UPOP.PAYTIMEOUT');
		$this->smsCode=getenv('UPOP.SMSCODE');
		$this->backUrl = getenv('UPOP.BACKURL');
		$this->frontUrl=getenv('UPOP.FRONTURL');
		$this->backTransUrl=getenv('UPOP.BACKTRANSURL');
		//$this->frontTransUrl=getenv('UPOP.FRONTTRANSURL');
		$this->certId = getenv('UPOP.CERTID');
		$this->port = getenv('UPOP.PORT');
		$this->queryUrl = getenv('UPOP.SINGLEQUERYURL');
		$this->encryptCert=getenv('UPOP.ENCRYPTCERT.PATH');
        $this->signCertPath=getenv('UPOP.SIGNCERT.PATH');
        $this->signCertType=getenv('UPOP.SIGNCERT.TYPE');
        $this->signCertPwd=getenv('UPOP.SIGNCERT.PWD');

        $this->middleCertPath=getenv('UPOP.MIDDLECERT.PATH');
        $this->rootCertPath=getenv('UPOP.ROOTCERT.PATH');

	}
	private function getSignature($merged_data=null){
		$success = self::initCert();
		$signData="";
		try{
		if ($success){
			$strData = self::convertToString($merged_data);

			$pkey = self::$keystore['pkey'];
			$signedData = self::generateSignature($pkey, $strData);
			
		}
		else
			$this->log->error("unable to read file");

			
			throw new \Exception("Error, contact system administrator");
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
		return $signedData;
	}
	private function initCert(){
		$success =false;

		
        if ($this->signCertType =='PKCS12'){
			try{
				if ($cert_store = file_get_contents($this->signCertPath)) {


						if (openssl_pkcs12_read($cert_store, self::$keystore, $this->signCertPwd)){
						   $this->log->info("Signed Certicate loaded Successfully");
							$success=true;
						}
						else{
							$this->log->error("unable to read file");

							throw new \Exception("Error, contact system administrator");

						}

				}
				else{
					$this->log->error("unable to read file");
					throw new \Exception("Error, contact system administrator");
				}
			}
			catch(\Exception $e){
				$this->log->error($e->getMessage());
			}
		}
		return $success ;
	}

	private function generateSignature($privateKey, $data=null){
		/* Ensure raw data is encoded using UTF-8, apply hasing. IMPORTANT that resulting hash is encoded 
		 * again using UTF-8
		 */
		//echo "data to be signed:". $data ."\r\n";
		$utf8=   utf8_encode ($data);

		$enc = self::generateHash($data);
		//echo "hash:". $enc ."\r\n";
		$signature = self::signData($enc, $privateKey);
		
		$b64 = base64_encode($signature);

    return $b64;
	}
	private function generateHash($utf8){
		//function used both for request and response. Response contain chinese characters and utf8_encode not applicable
		$sha256 = hash ("sha256",$utf8);
		$utf8_enc=   utf8_encode ($sha256); //enchode the hashed data
	return $utf8_enc; 	
	}
	private function signData($enc , $privateKey){
		$alg = getenv('UPOP.ALG');
		$signature = "";
		try{
			if (openssl_sign ( $enc , $signature ,  $privateKey, $alg)){
				//success

			}
			else{
				$this->log->error("unable to read cert file");
				throw new \Exception("Error, contact system administrator");
			}
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
	return $signature;
		
	}


	public function makeRequest($requestData){
		parent::makeRequest($requestData);
	}
    public function curlPost(array $data, $url,$port){
		//echo "url:". $url;

		$headers = ["Content-type:application/x-www-form-urlencoded;charset=UTF-8"];
		$request_time = new \DateTime();
		$strData = "";
		$output="";
		try{
			if(!is_string($url)){
				$this->log->error('URL must be a string!');
				throw new \InvalidArgumentException('Error, contact system administrator');
			}
			else{
				foreach($data as $key => $value) {
					$strData.= $key."=";

						$strData.= urlencode($value);

						$strData.="&";

				}
				$strData = substr($strData,0,strlen($strData)-1);
				$this->log->error("resquest data:". $strData);



				//init curl
				$curl = curl_init();


				curl_setopt($curl, CURLOPT_URL, $url);
				curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
				curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
				//set request headers
				curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
				curl_setopt($curl, CURLOPT_PORT, $port);

				//request method is POST
				curl_setopt($curl, CURLOPT_POST, 1);
				//request body
				curl_setopt($curl, CURLOPT_POSTFIELDS, $strData);


				//return transfer response as string to the $curl resource
				curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);

				//output verbose info
				curl_setopt($curl, CURLOPT_VERBOSE, 1);

				$output = curl_exec($curl);
				//Utils::infoMsg($output);
				$this->log->info("response received:". $output);
				//echo $output;
			}

		}
		catch(\Exception $e){
				$this->log->error($e->getMessage());
		}

	return $output;

	}
	
	public function encryptCardData($cardDetails){
		/*
			This function excrypts card information using a public key
		*/
		$encryptCert= self::getEncryptCertPath();

        $publickey = openssl_pkey_get_public($encryptCert);
        $keyData = openssl_pkey_get_details($publickey);
	    $key=$keyData['key'];
		openssl_public_encrypt($cardDetails, $enc, $key, OPENSSL_PKCS1_PADDING);   
    	$cardEnc = base64_encode($enc);
	return $cardEnc;	
	}
	
	public function encryptedCertId(){
		/*
			This funcitons retrieves the certificate identifier
		*/
		$encryptCert= self::getEncryptCertPath();
		
		$data=openssl_x509_parse($encryptCert,true);
		$serialNo = $data['serialNumber'];
	return $serialNo;
	}
	private function getEncryptCertPath(){
	/*
		Function to get the certificate to use for encryption
	*/
		$encrypted="";
		try{
			if ($enCertPath = file_get_contents($this->encryptCert)) {

			}
			else{
				$this->log->error("unable to read cert file");
				throw new \Exception("Error: Unable to proceed\n");

			}
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
		return $enCertPath;
	}

	public function encryptCustomerInfo(array $customerInfo, $card_number){
	/*	Function receives card details and card number. If pin is provided as part of input then this is 		base64 encoded with card number otherwise only card details only are encoded
	*/
		foreach ($customerInfo as $key=>$value){
			if($key==="phoneNo" || $key==="cvn" || $key==="expired"){
				$strData.= $key."=".$value."&";


			}
			else{ 
				if ($key==="pin" && strlen(trim($card_number))>0){
					// to be implemented according to SDK
				}
				$strData = $key."=".$value."&";
			}

		}
	    $strData = "{" . substr($strData,0,strlen($strData)-1) . "}";

	    $customerInfoEnc = base64_encode($strData);
		//echo "customer info enc:" . $customerInfoEnc;
	 return $customerInfoEnc;
	}
	protected function decryptCustomerInfo($package, $pass){
		openssl_pkcs12_read($cert_store, $certs, $pass);
		$res=$certs['pkey'];
		$b64dec = decodeSign($package);

		openssl_private_decrypt($b64dec,$decrypted,$res);
		//echo "plain text ". $decrypted."<br />";

	}

	
	public function isPubKeyCertValid($pubCertStr){
		$cert = openssl_x509_parse($pubCertStr);
		$isValid = "True";
		
		if( $cert['validFrom_time_t'] > time() || $cert['validTo_time_t'] < time() )
			$isValid = "false";
		else{
			//self::initMiddleCert();
			//self::initRootCert();
			$intermediateCerts=[$this->middleCertPath, $this->rootCertPath];
			try{
				$success = openssl_x509_checkpurpose($pubCertStr,X509_PURPOSE_ANY,$intermediateCerts);
				//echo "validation:".$success;
				if (!$success){
					$isValid="False";
					throw new \Exception("Certificate validation failed");
				}
			}
				
			catch(Exception $e){
				$this->log->error($e->getMessage());

			}

			//$intermediateCerts=self::$middleCert.self::$rootCert.$pubCertStr;
		}
		
	return $isValid;
	}
	public function isCertValid($cert){
		
	}
	public function isDataValid(array $ares){
		$signature = $ares["signature"];

		unset($ares['signature']);
		//echo "<br />";
		//print_r($ares);
		$pubKeyStr=  $ares["signPubKeyCert"];
		$strData = self::convertToString($ares);
		print_r($strData);
		$strDataEnc = self::generateHash($strData);
		//echo "string to verify:". $strDataEnc ."\n";
		$decodedStr = self::decodeSgn($signature);
		//echo "decoded signature:". $decodedStr ."<br />";
		$pubkey= openssl_x509_read($pubKeyStr);
		$alg = getenv('UPOP.ALG');
		$success = false;
		
		if (openssl_verify($strDataEnc,$decodedStr,$pubkey,$alg )){
			$success=true;
		}
		//$success = openssl_verify($strDataEnc, $b64,$pubkey);
		//echo "status of verification:". $success;
		return $success;

	}
	
	
	public function decodeSgn($pkg){
		//echo "package:". $pkg;
		$decodedPkg  = base64_decode($pkg);
	 return $decodedPkg;
		
	}

	public function processRequest($merged_data=null, $requiredData=null){
	/*

	* i.  validate merged array
	* ii.   get keystore
	* iii. generate signature
	*/
	$oData = (object) $merged_data; //make object for validation 
	$isValid = self::isRequestValid($oData,$requiredData);

	if ($isValid){
		$signature	= self::getSignature($merged_data);
	}
	else{
		return $isValid;
	}
	return $signature;

	}	
/*
	public function mergeData($defaultContent=null,$userData=null, $type){
		$type = ["txnType"=>$this->txntype,"txnSubType"=>$this->txnSubType];
		$merged_data = parent::mergeData($defaultContent,$userData,$type);

		return $merged_data;
	}
*/
	private function convertToString($merged_final=null){
        $strData = null;
        ksort($merged_final);
		//print_r($recd);

            foreach($merged_final as $key => $value) {
                $strData.= $key."=".$value."&";

            }
        $strData = substr($strData,0,strlen($strData)-1);
		return $strData;
	}

    private function isRequestValid($recd=null, $required=null){
        /**
        
        @param recd data received from requester
        @param required fields required for processing
        
        **/
        $valid = false;
        try{
            if(empty($recd)){
                throw new \InvalidArgumentException('Invalid request made');
            }
            $valid = self::validateRequest($recd, $required);
        }
        catch(InvalidArgumentException $e){
           	$this->log->error($e->getMessage());
        }
        return $valid;
    }


	public function initiateRequest(array $reqData, $url, $port){
		$response = self::curlPost($reqData, $url, $port);

		return $response;

	}
    
	public function validateRequest($raw_input, array $required_params){
	/*
		Validation of request to ensure it has the mandatory fields required
	*/
		$res_arr = null;
        $res_obj = null;
		try{
			if($raw_input){
				foreach($required_params as $param){
					//take not that empty("0") evaluates to a false;
					if(!property_exists($raw_input, $param) || (empty($raw_input->$param) 
						&& strlen($raw_input->$param)== 0) || !(is_string($raw_input->$param) || is_int($raw_input->$param))){
						die($param . ' is required');
					}
					else{
						$res_arr[$param] = $raw_input->$param;
					}
				}
				$res_obj = (object) $res_arr;
			}
			else{
				throw new \Exception('The following parameters are required ' . json_encode($required_params));
			}
		}
		catch(\Exception $e){
			$this->log->error($e->getMessage());
		}
    return $res_obj;
    }


	public function getDefaultContent(){
		
        $content = array(
            "version"=>$this->version,
            "encoding"=>$this->encoding,
            "signMethod" =>$this->signMethod, 
            "bizType"=>$this->bizType,
            "accessType"=>$this->accessType,
            "merId"=>$this->merId,
            "certId" => $this->certId,
        );
    
        return $content;
    }
	public function getPurchaseContent(){
	/*
		Additional fields required for making purchase, purchase cancellation, preauthorization  requests. The data is stored in the .env file
	*/
		 $content = array(
		"channelType"=>$this->channelType,
		"backUrl"=> $this->backUrl
		 );
			 
	return $content;
	}
	private function getRefundContent(){
		 $content = array(
		"channelType"=>$this->channelType,
		"backUrl"=> $this->backUrl
		 );
			 
	return $content;
	}
	public function getPreauthContent(){
		 $content = array(
		"channelType"=>$this->channelType,
		"currencyCode"=>$this->currencyCode,
		"frontUrl"=> $this->frontUrl,
		"backUrl"=> $this->backUrl
		 );
			 
	return $content;
	}
    public function getRequiredFlds(){
        $required_data = [
            'version',
            'encoding',
            'signMethod',
            'txnType',
            'txnSubType',
            'bizType',
            'accessType',
            'merId',
            'orderId',
            'txnTime',
            'certId'
        ];
        return $required_data;
    }
  /*  public function getBasicInputsRequired(){
	
		Return an array of basic fields that are required for any unionpay transaction. These fields include
		order id , time transaction in taking place and type of transacton such as purchase, preauthorization, refund,
		Three items
	
		
        //$requiredInputs=['orderId','txnTime','type'];
		$requiredInputs=['type'];
		return $requiredInputs;
    }*/
	
    public function getLogFile($tag="iPay"){
		
        $dirname = getenv('LOGDIR');

       // echo "dir: ". $dirname;}
        try{
			if(!is_string($dirname)){
				throw new \InvalidArgumentException('dirname must be a string');
			}
			else{
				// $logs    = (is_array($logs))? json_encode($logs, JSON_PRETTY_PRINT): (string)$logs;

				$dir = $dirname;

				$base_dir = dirname(__dir__).'/';

				$save_dir = $base_dir.$dirname;

				$dir_exists = (file_exists($save_dir) && is_dir($save_dir));

				if(!$dir_exists){
					if(!mkdir($save_dir, 0755, true)){
						throw new \Exception('Unable to create directory');
					}
				}
				$dir = $save_dir;
				$logFile = $dir."/".date("Y-m-d").'.log';
				$this->log = new Logger($tag);
				$this->log->pushHandler(new StreamHandler($logFile , Logger::INFO));

			}
		}
		catch (\Exception $e){
			$this->log->error($e->getMessage());
		}
    }

	
}
/*
This execution begins here by setting ups values

*/
error_reporting(E_ALL);
ini_set('display_errors', TRUE);

ini_set('display_startup_errors', TRUE);
// load the dotenv file
$dotenv = Dotenv::createImmutable(__DIR__);
$dotenv->load();


/*
$dotenv = new \Dotenv\Dotenv(__DIR__.'/secure');
$dotenv->load();
*/
$dataRecd = file_get_contents('php://input');
$isRequestJson = (json_decode($dataRecd) != NULL) ? true : false;
$unionpay = new UnionPay(); //instantiate unionpay class
$unionpay->getLogFile("upop");
try{
	if ($isRequestJson){
		$requiredUserData = ['type'] ;// inital required input that has to be present to determine transaction processing
		$json = json_decode($dataRecd); 
		//check that json request has the basic required inputs. Further validation will be done for each transation type
		// the initial validation of json input in order to determine which task to perform
		$isValid = $unionpay->validateRequest($json,$requiredUserData);


		if ($isValid){

			$class = null;
			// fields required are for de
			$requiredFlds = $unionpay->getRequiredFlds();
			$url = $unionpay->backTransUrl;
			switch ($json->type){
				case $unionpay::PURCHASE:
					// purchase
					//$var = 'Purchase';
                    $txntype=getenv('UPOP.PUR.TXNTYPE');
                    $txnSubType=getenv('UPOP.TXNSUBTYPE');
                    $encryptedCertId = $unionpay->encryptedCertId();
                    $combined=[];
                    $requiredUserData = ['card','cvn','expiry','phoneno','txnAmt','txnTime'];
                    $unionpay->validateRequest($json,$requiredUserData);
                    
                    if($json->card===""){	
                        throw new \Exception("Please provide card details");

                    }
                    else{
                        
                        if($json->expiry==="" && $json->cvn==="" && $json->phoneno==="" && $json->card){
                                $requiredUserData = ["smsCode"];
                                $unionpay->validateRequest($json,$requiredUserData);

                                if ($json->smsCode===""){
                                    throw new \Exception("Please provide card details");

                                }
                                else{
                                    $customerInfo =["smsCode"=>  $unionpay->smsCode];
                                }
                            }
                            else{

                                $cardDetails ="expired=".$json->expiry."&cvn2=". $json->cvn. "&phoneNo=". $json->phoneno;
                                // card details such as expiry month, year and cvv encrypted seperately from card number 
                                $encryptedInfo = $unionpay->encryptCardData($cardDetails);
                                $encryptedCard = $unionpay->encryptCardData($json->card);
                                //incase of presence of SMS code functionality it is combined with encrypted card details
                                $customerInfo = ["smsCode"=>  $unionpay->smsCode,"encryptedInfo"=>$encryptedInfo];
                            }
                        $encryptedCustomerInfo =  $unionpay->encryptCustomerInfo($customerInfo,$json->card);
                        $customerData = ["accNo"=>$encryptedCard, "encryptCertId"=>$encryptedCertId,"customerInfo"=>$encryptedCustomerInfo,"txnAmt"=> $json->txnAmt,"currencyCode"=$json->currency];
                        $purchaseContent = $unionpay->getPurchaseContent();
                        $combined = array_merge($purchaseContent,$customerData);
                        // add additional fields for validation 
                        array_push($requiredFlds, 'txnAmt','channelType','currencyCode','backUrl');
                    }
                    break;
				case $unionpay::CANCELPURCHASE:
					//$var = 'PurchaseCancel';
					//$url = $unionpay->backTransUrl;

					$txntype =getenv('UPOP.PUR.CANCEL.TXNTYPE');
					$txnSubType=getenv('UPOP.GLOBAL.TYPE');

					$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt,"currencyCode"=>$json->currency];
					$purchaseContent = $unionpay->getPurchaseContent();
					$combined = array_merge($purchaseContent,$customerData);
					array_push($requiredFlds,'txnAmt','channelType','currencyCode','backUrl','origQryId');

					//purchase Cancel
					break;
				case $unionpay::REFUND:
					// refund
					//$url = $unionpay->backTransUrl;

					$txntype = getenv('UPOP.REFUND.TXNTYPE');
					$txnSubType = getenv('UPOP.GLOBAL.TYPE');
					$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt];
					$purchaseContent = $unionpay->getRefundContent();
					$combined = array_merge($purchaseContent,$customerData);
					array_push($requiredFlds,'txnAmt','channelType','backUrl','origQryId');


					break;
				case $unionpay::PREAUTH:
					//PreAuth
					//$url = $unionpay->backTransUrl;

					$txntype=getenv('UPOP.PREAUTH.TXNTYPE');
					$txnSubType=getenv('UPOP.TXNSUBTYPE');

					$duration = getenv('UPOP.PAYTIMEOUT');

					$time = new \DateTime(date("Y-m-d H:i:s"));
					$timezone = new \DateTimeZone('Africa/Nairobi');
					$time->setTimezone($timezone);
					//echo "time: ".$time->format('Y-m-d H:i');
					//echo 'duration='.$txnSubType;
					$time->add(new \DateInterval('PT' . $duration . 'M'));

					$payTimeOut = $time->format('YmdHis');
					if($json->expiry==="" && $json->cvn==="" && $json->phoneno===""){
						if ($json->smsCode===""){
							new \Exception("Invalid request");

						}
						else{
							$customerInfo =["smsCode"=>  $unionpay->smsCode];
						}
					}
					else{
						$cardDetails ="expired=".$json->expiry."&cvn2=". $json->cvn. "&phoneNo=". $json->phoneno;
						$encryptedInfo = $unionpay->encryptCardData($cardDetails);

						$customerInfo = ["encryptedInfo"=>$encryptedInfo];
					}
					$encryptedCard = $unionpay->encryptCardData($json->card);
					$encryptedCertId = $unionpay->encryptedCertId();
					$encryptedCustomerInfo =  $unionpay->encryptCustomerInfo($customerInfo,$json->card);
					$customerData = ["accNo"=>$encryptedCard, "encryptCertId"=>$encryptedCertId,"customerInfo"=>$encryptedCustomerInfo,"txnAmt"=> $json->txnAmt, "payTimeout"=>$payTimeOut];

					//$customerData = [ "txnAmt"=> $json->txnAmt,"payTimeout"=>$payTimeOut];
					$purchaseContent = $unionpay->getPreauthContent();
					$combined = array_merge($purchaseContent,$customerData);
					array_push($requiredFlds,'txnAmt','channelType','backUrl','frontUrl', 'payTimeout');


					break;
				case $unionpay::CANCELPREAUTH:
					//$url = $unionpay->backTransUrl;

					$txntype=getenv('UPOP.PREAUTH.CANCEL.TXNTYPE');
					$txnSubType=getenv('UPOP.GLOBAL.TYPE');

					$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt];
					$purchaseContent = $unionpay->getPurchaseContent();
					$combined = array_merge($purchaseContent,$customerData);
					array_push($requiredFlds,'txnAmt','channelType','currencyCode','backUrl','origQryId');

					break;
				case $unionpay::COMPLETEPREAUTH:
					//PreAuth Complete
					//$url = $unionpay->backTransUrl;

					$txntype=getenv('UPOP.PREAUTH.COMPLETE.TXNTYPE');
					$txnSubType=getenv('UPOP.GLOBAL.TYPE');

					$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt];
					$purchaseContent = $unionpay->getPurchaseContent();
					$combined = array_merge($purchaseContent,$customerData);
					array_push($requiredFlds,'txnAmt','channelType','currencyCode','backUrl','origQryId');

					break;

				case $unionpay::CANCELCOMPLETEPREAUTH:
					//PreAuth Complete Cancel
					//$url = $unionpay->backTransUrl;

					$txntype=getenv('UPOP.PREAUTHCC.TXNTYPE');
					$txnSubType=getenv('UPOP.GLOBAL.TYPE');

					$customerData = ["origQryId"=>$json->serialno, "txnAmt"=> $json->txnAmt];
					$purchaseContent = $unionpay->getPurchaseContent();
					$combined = array_merge($purchaseContent,$customerData);
					array_push($requiredFlds,'txnAmt','channelType','currencyCode','backUrl','origQryId');

					break;

				case $unionpay::RECURRING:
					//$url = $unionpay->backTransUrl;

					$txntype=getenv('UPOP.RECUR.TXNTYPE');
					$txnSubType=getenv('UPOP.TXNSUBTYPE');

					//Recurring
					break;
				case $unionpay::QUERY:
					//query
					$txntype=getenv('UPOP.FAIL.TYPE');
					$txnSubType=getenv('UPOP.GLOBAL.TYPE');
					//$custInfo = new CustomerInfo($txntype, $txnSubType);
					$url = $unionpay->queryUrl;

					$combined = ["certType"=>"01"];
					array_push($requiredFlds,'certType');

					break;

				default:
					new \Exception ("invalid type");

			}
			$defaultContent = $unionpay->getDefaultContent();
			//print_r($defaultContent);


			$defaultContent=array_merge($defaultContent,(array)$combined);

			//$merged = $classobj->mergeData($defaultContent, $json, $type = null);
			$types = ["txnType"=>$txntype,"txnSubType"=>$txnSubType];
			$userData = ["orderId"=>$json->orderId,"txnTime"=>$json->txnTime];
			$merged = array_merge($defaultContent, $userData,$types);

			//$merged = $unionpay->mergeData($defaultContent, $userData, $types);
			$sort = ksort($merged);
			//var_dump($merged);
			//$signature = $classobj->processRequest($merged, $requiredFlds);
			$signature = $unionpay->processRequest($merged, $requiredFlds);
			//echo "signature: ". $signature. "\n";


			//$certID = $upopconf->certid;
			//$certDetail = ["signature"=>$signature,"certId"=>$certID];
			$certDetail = ["signature"=>$signature];
			$merged_final= array_merge($merged,$certDetail);

			// $sorted = ksort($merged_final);
			//var_dump($merged_final);
			$port = $unionpay->port;
			//$data = $classobj->initiateRequest($merged_final,$url,$port);
			$data = $unionpay->initiateRequest($merged_final,$url,$port);
			print_r($data);
			if(strlen($data) < 1){
				throw new \Exception('Error, contact system administrator');
			}
			//echo "response:". $data. "<br/>";
			$ares = explode("&",$data);
			//Svar_dump($ares);
			//$resp="";
			

			foreach( $ares as $item){
				$temp = explode("=",$item); //accNo will lose the == and this should be returned
				$key=$temp[0];
				//var_dump($temp);
				if($key==='accNo')
					$value=$temp[1]."=="; //return these == lost during explode
				else
					$value=$temp[1];

				$resp[$key] =  $value;

			}


			foreach($resp as $key => $value ){
			   if (  $key==='signPubKeyCert'){
				   $pubcertStr=$value;
				   break;
			   }
			}
			$respCode = $resp['respCode'] ;
			//print_r($resp);
			$validCert = $unionpay->isPubKeyCertValid($pubcertStr);
			if ($validCert){

				if ($respCode =='00'){
					$validData = $unionpay->isDataValid($resp);

					if ($validData){
						$queryId= $resp['queryId']	;

						echo '{
							"status":"200",
							"description":"OK",
							"queryId":"'.$queryId.'",
							"respCode":"'.$respCode.'"

						}';
					}
					else{
						echo '{
								"status":"400",
								"description":"Error, contact system administrator",
								"respCode":"'."99".'"

							}';
					}

				}
				else{
					echo '{
						"status":"400",
						"description":"failed",
						"respCode":"'.$respCode.'"

					}';
				}
			}	
			else{
				die("certificate not valid");
			}

		}
		else{
			echo '{
				"status":"400",
				"description":"Missing required Field. Please ensure card details and/or sms code is provided";

			}';

		}

	}
	else{

		new \Exception ("invalid JSON request");

	}
}
catch(\Exception $e){
			echo '{
			"status":"400",
			"description":"'. $e->getMessage().
		'"
		}';
}

?>