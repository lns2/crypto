"use strict";


/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    version: undefined,
    secrets: { 
               hmac: undefined,
               enc: undefined,
               verif: undefined},
    data: { } //KVS
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;

  // Flag to indicate whether password manager is "ready" or not
  var ready = false;

  //Valores para gerar as chaves

  var enc_gen = "afsfjkaADasdjADkahSasad";
  var hmac_gen = "IAYDikADYmnuksnmhfakfh";
  var verif_gen = "AduhsjakhUAHDuLJjfAIU";

  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    priv.version = "CS 255 Password Manager v1.0";
    //Salt
    priv.salt = random_bitarray(128);

    //Master key
    var masterKey = KDF(password, priv.salt);
  
    //Keys
    priv.secrets.hmac = HMAC(masterKey, hmac_gen);
    priv.secrets.enc = bitarray_slice(HMAC(masterKey, enc_gen), 0, 128);
    priv.secrets.verif = bitarray_slice(HMAC(masterKey, verif_gen), 0, 128);

    ready = true;

  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    ready = false; //Só é modificado se chegar ao final da função.
    
    if (trusted_data_check !== undefined) {
      var repr_sha = SHA256(string_to_bitarray(repr));
      var check = bitarray_equal(repr_sha, trusted_data_check);
      if (!check) {
        throw "Check invalid";
      }
    }

    var data = JSON.parse(repr);
    var salt = data["salt"]; 
    var verification = data["verification"];

    var masterKey = KDF(password, salt);

    var verifCheck = bitarray_slice(HMAC(masterKey, verif_gen), 0, 128);
    var verifString;

     try {
      verifString = dec_gcm(setup_cipher(verifCheck), verification);

     } catch(err) {
      return false;

     }

     //Checa se verificação é válida
     if (!bitarray_equal(verifString, string_to_bitarray(verif_gen))) {
      return false;

    }

     
     priv.secrets.verif = verifCheck;
     priv.secrets.hmac = HMAC(masterKey, hmac_gen);
     priv.secrets.enc = bitarray_slice(HMAC(masterKey, enc_gen), 0, 128);
     priv.salt = salt;
     priv.data = data["privData"];


     ready = true;
    
     return true;


  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    *
    * Return Type: array
    */ 
  keychain.dump = function() {
    if (!ready) {
      return null;
    }
          
    var verification = enc_gcm(setup_cipher(priv.secrets.verif), string_to_bitarray(verif_gen));

    var data = {};
    data["privData"] = priv.data;
    data["salt"] = priv.salt;
    data["verification"] = verification;
        
    var keychain_string = JSON.stringify(data);
    var checksum = SHA256(string_to_bitarray(keychain_string));

    var arr = [keychain_string, checksum];
    
    return arr;
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (!ready) {
      throw "Keychain not ready."
    }
    
    var domain = HMAC(priv.secrets.hmac,name);
   
    if (priv.data[domain] !== undefined) {
      //Senha concatenada
      var decrypt = dec_gcm(setup_cipher(priv.secrets.enc), priv.data[domain]);

      var recDomain = bitarray_slice(decrypt, 0, bitarray_len(domain));
      
      var paddedPassword = bitarray_slice(decrypt, bitarray_len(domain), bitarray_len(decrypt));
      var password = string_from_padded_bitarray(paddedPassword, MAX_PW_LEN_BYTES); 

      if (bitarray_equal(domain, recDomain)) {
          return password;
        } else {
          throw "Swap Attack detected!";
        }
    
      
    } else {
      return null;
    }



  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (!ready) {
      throw "Keychain not ready."
    }

    var domain = HMAC(priv.secrets.hmac, name);

    //Extensão da senha para 64 bytes
    var paddedValue = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES);

    //Concatenação do domínio e senha
    var genPassword = bitarray_concat(domain, paddedValue);
                
    var encriptedPassword = enc_gcm(setup_cipher(priv.secrets.enc), genPassword);
       
    priv.data[domain] = encriptedPassword;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if (!ready) {
      throw "Keychain not ready."
    }

    var domain = HMAC(priv.secrets.hmac, name);


    if (priv.data[domain] !== undefined) {
      delete priv.data[domain];
      return true;
    } else {
      return false;
    }
  }

  return keychain;
}

module.exports.keychain = keychain;
