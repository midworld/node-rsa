#include "node_rsa.h"

#include <v8.h>

#include <node.h>
#include <node_buffer.h>

#include <string.h>
#include <stdlib.h>

#include <errno.h>

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
# define OPENSSL_CONST const
#else
# define OPENSSL_CONST
#endif

#if defined(_WIN32) || defined(_WIN64) 
  #define snprintf _snprintf 
  #define vsnprintf _vsnprintf 
  #define strcasecmp _stricmp 
  #define strncasecmp _strnicmp 
#endif

namespace node {

using namespace v8;

void RsaKeypair::Initialize(Handle<Object> target) {
  HandleScope scope;

  Local<FunctionTemplate> t = FunctionTemplate::New(RsaKeypair::New);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("RsaKeypair"));

  NODE_SET_PROTOTYPE_METHOD(t, "setPublicKey",
                            RsaKeypair::SetPublicKey);
  NODE_SET_PROTOTYPE_METHOD(t, "setPrivateKey",
                            RsaKeypair::SetPrivateKey);
  NODE_SET_PROTOTYPE_METHOD(t, "setPadding",
                            RsaKeypair::SetPadding);
  NODE_SET_PROTOTYPE_METHOD(t, "encryptSync",
                            RsaKeypair::EncryptSync);
  NODE_SET_PROTOTYPE_METHOD(t, "decryptSync",
                            RsaKeypair::DecryptSync);
  NODE_SET_PROTOTYPE_METHOD(t, "encrypt",
                            RsaKeypair::Encrypt);
  NODE_SET_PROTOTYPE_METHOD(t, "decrypt",
                            RsaKeypair::Decrypt);
  NODE_SET_PROTOTYPE_METHOD(t, "getModulus",
                            RsaKeypair::GetModulus);
  NODE_SET_PROTOTYPE_METHOD(t, "getExponent",
                            RsaKeypair::GetExponent);
  NODE_SET_PROTOTYPE_METHOD(t, "getPadding",
                            RsaKeypair::GetPadding);

  target->Set(String::NewSymbol("RsaKeypair"), t->GetFunction());
}

Handle<Value> RsaKeypair::New(const Arguments& args) {
  HandleScope scope;
  RsaKeypair *p = new RsaKeypair();
  p->Wrap(args.Holder());
  p->privateKey = NULL;
  p->publicKey = NULL;
  p->padding = RSA_PKCS1_OAEP_PADDING;
  return args.This();
}

Handle<Value> RsaKeypair::SetPublicKey(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (args.Length() != 1 ||
      !args[0]->IsString()) {
    return ThrowException(Exception::TypeError(
          String::New("Bad parameter")));
  }
  String::Utf8Value pubKey(args[0]->ToString());

  BIO *bp = NULL;
  RSA *key = NULL;

  bp = BIO_new(BIO_s_mem());
  if (!BIO_write(bp, *pubKey, strlen(*pubKey)))
    return False();

  key = PEM_read_bio_RSA_PUBKEY(bp, NULL, NULL, NULL);
  if (key == NULL)
    return False();

  kp->publicKey = key;
  BIO_free(bp);

  return True();
}

Handle<Value> RsaKeypair::SetPrivateKey(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (args.Length() == 2 &&
      (!args[0]->IsString() || !args[1]->IsString())) {
    return ThrowException(Exception::TypeError(
          String::New("Bad parameter")));
  }
  if (args.Length() == 1 &&
      (!args[0]->IsString())) {
    return ThrowException(Exception::TypeError(
          String::New("Bad parameter")));
  }

  BIO *bp = NULL;
  String::Utf8Value privKey(args[0]->ToString());

  bp = BIO_new(BIO_s_mem());
  if (!BIO_write(bp, *privKey, strlen(*privKey)))
    return False();

  RSA *key;
  if (args.Length() == 2) {
    String::Utf8Value passphrase(args[1]->ToString());
    key = PEM_read_bio_RSAPrivateKey(bp, NULL, 0, *passphrase);
  }
  else {
    key = PEM_read_bio_RSAPrivateKey(bp, NULL, 0, NULL);
  }
  if (key == NULL) {
    return False();
  }

  kp->privateKey = key;
  BIO_free(bp);

  return True();
}

Handle<Value> RsaKeypair::SetPadding(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  String::Utf8Value padding(args[0]->ToString());

  if (strcasecmp(*padding, "oaep") == 0)
    kp->padding = RSA_PKCS1_OAEP_PADDING;
  else if (strcasecmp(*padding, "pkcs1") == 0)
    kp->padding = RSA_PKCS1_PADDING;
  else if (strcasecmp(*padding, "sslv23") == 0)
    kp->padding = RSA_SSLV23_PADDING;
  else if (strcasecmp(*padding, "none") == 0)
    kp->padding = RSA_NO_PADDING;
  else {
    Local<Value> exception = Exception::Error(String::New("RsaKeypair.setPadding "
                                  "can be oaep (default), pkcs1, sslv23 or none"));
	  return ThrowException(exception);
  }
    
  return True();
}

Handle<Value> RsaKeypair::EncryptSync(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (kp->publicKey == NULL) {
    Local<Value> exception = Exception::Error(String::New("Can't encrypt, no public key"));
    return ThrowException(exception);
  }
  
  enum encoding enc = MyParseEncoding(args[1]);
  ssize_t len = DecodeBytes(args[0], enc);
  
  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  ssize_t paddingLength = -1;
  switch (kp->padding) {
    case RSA_PKCS1_OAEP_PADDING:
      paddingLength = 41;
      break;
    case RSA_PKCS1_PADDING:
    case RSA_SSLV23_PADDING:
      paddingLength = 11;
      break;
  }
  
  // check per RSA_public_encrypt(3) when using padding modes
  if (len > RSA_size(kp->publicKey) - paddingLength) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument (too long for key size)"));
    return ThrowException(exception);
  }

  unsigned char* buf = new unsigned char[len];
  ssize_t written = DecodeWrite((char *)buf, len, args[0], enc);
  assert(written == len);  

  int out_len = RSA_size(kp->publicKey);
  unsigned char *out = (unsigned char*)malloc(out_len);

  uv_mutex_lock(&kp->mutex);
  int r = RSA_public_encrypt(len, buf, out, kp->publicKey, kp->padding);
  uv_mutex_unlock(&kp->mutex);

  delete[] buf;

  if (r < 0) {
    if (out) free(out);

    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<String> full_err = String::Concat(String::New("RSA encrypt: "), String::New(err));
    Local<Value> exception = Exception::Error(full_err);
    return ThrowException(exception);
  }

  Local<Value> outString;
  if (out_len == 0) {
    outString = String::New("");
  }
  else {
    outString = Encode(out, out_len, BINARY);
  }

  if (out) free(out);
  
  return scope.Close(outString);
}

Handle<Value> RsaKeypair::Encrypt(const Arguments& args) {
  HandleScope scope;

  //printf("argc=%d\n", args.Length());
  //auto printString = [](Local<Value> x) {
  //  if (!x->IsString())
  //    return;
  //  char* bufx = new char[4096];
  //  memset(bufx, 4096, 0);
  //  x->ToString()->WriteUtf8(bufx);
  //  printf("%s\n", bufx);
  //};

  //printString(args[0]);
  //printString(args[1]);

  if (args.Length() < 3 || !args[2]->IsFunction()) {
    return ThrowException(Exception::TypeError(
      String::New("Bad argument")));
  }

  Local<Function> callback = Local<Function>::Cast(args[2]);

  RsaKeypair* kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (kp->publicKey == NULL) {
    Local<Value> exception = Exception::Error(String::New("Can't encrypt, no public key"));
    return ThrowException(exception);
  }

  enum encoding enc = MyParseEncoding(args[1]);
  ssize_t len = DecodeBytes(args[0], enc);

  if (len < 0) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument"));
    return ThrowException(exception);
  }

  ssize_t paddingLength = -1;
  switch (kp->padding) {
    case RSA_PKCS1_OAEP_PADDING:
      paddingLength = 41;
      break;
    case RSA_PKCS1_PADDING:
    case RSA_SSLV23_PADDING:
      paddingLength = 11;
      break;
  }

  // check per RSA_public_encrypt(3) when using padding modes
  if (len > RSA_size(kp->publicKey) - paddingLength) {
    Local<Value> exception = Exception::TypeError(String::New("Bad argument (too long for key size)"));
    return ThrowException(exception);
  }

  unsigned char* buf = new unsigned char[len];
  ssize_t written = DecodeWrite((char *)buf, len, args[0], enc);
  assert(written == len);  

  Baton* baton = new Baton();
  baton->reqeust.data = baton;
  baton->callback = Persistent<Function>::New(callback);
  baton->keyPair = kp;
  baton->buf = buf;
  baton->len = len;
  baton->mode = Baton::MODE_ENCRYPT;

  uv_queue_work(uv_default_loop(), &baton->reqeust, AsyncWork, AsyncAfter);

  return Undefined();
}

Handle<Value> RsaKeypair::DecryptSync(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (kp->privateKey == NULL) {
    Local<Value> exception = Exception::Error(String::New("Can't decrypt, no private key"));
    return ThrowException(exception);
  }

  ssize_t len = DecodeBytes(args[0], BINARY);
  unsigned char* buf = new unsigned char[len];
  (void)DecodeWrite((char *)buf, len, args[0], BINARY);
  //unsigned char* ciphertext;
  //int ciphertext_len;
  
  // XXX is this check unnecessary? is it just len <= keysize?
  // check per RSA_public_encrypt(3) when using OAEP
  //if (len > RSA_size(kp->privateKey) - 41) {
  //  Local<Value> exception = Exception::Error(String::New("Bad argument (too long for key size)"));
  //  return ThrowException(exception);
  //}
  
  int out_len = RSA_size(kp->privateKey);
  unsigned char *out = (unsigned char*)malloc(out_len);
  
  uv_mutex_lock(&kp->mutex);
  out_len = RSA_private_decrypt(len, buf, out, kp->privateKey, kp->padding);
  uv_mutex_unlock(&kp->mutex);

  if (out_len < 0) {
    if (out) free(out);
    delete[] buf;

    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<String> full_err = String::Concat(String::New("RSA decrypt: "), String::New(err));
    Local<Value> exception = Exception::Error(full_err);
    return ThrowException(exception);
  }
  
  Local<Value> outString;
  if (out_len == 0) {
    outString = String::New("");
  } else if (args.Length() <= 2 || !args[2]->IsString()) {
    outString = Encode(out, out_len, BINARY);
  } else {
    enum encoding enc = MyParseEncoding(args[2]);
    outString = Encode(out, out_len, enc);
  }

  if (out) free(out);
  delete[] buf;
  return scope.Close(outString);
}

Handle<Value> RsaKeypair::Decrypt(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 4 || !args[3]->IsFunction()) {
    return ThrowException(Exception::TypeError(
      String::New("Bad argument")));
  }

  Local<Function> callback = Local<Function>::Cast(args[3]);

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  if (kp->privateKey == NULL) {
    Local<Value> exception = Exception::Error(String::New("Can't decrypt, no private key"));
    return ThrowException(exception);
  }

  ssize_t len = DecodeBytes(args[0], BINARY);
  unsigned char* buf = new unsigned char[len];
  (void)DecodeWrite((char *)buf, len, args[0], BINARY);

  Baton* baton = new Baton();
  baton->reqeust.data = baton;
  baton->callback = Persistent<Function>::New(callback);
  baton->keyPair = kp;
  baton->buf = buf;
  baton->len = len;
  baton->mode = Baton::MODE_DECRYPT;
  baton->enc = MyParseEncoding(args[2]);
  
  uv_queue_work(uv_default_loop(), &baton->reqeust, AsyncWork, AsyncAfter);

  return Undefined();
}

Handle<Value> RsaKeypair::GetBignum(const Arguments& args, WhichComponent which) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());
  RSA *target = (kp->privateKey != NULL) ? kp->privateKey : kp->publicKey;

  if (target == NULL) {
    Local<Value> exception = Exception::Error(String::New("No key set"));
    return ThrowException(exception);
  }

  BIGNUM *number = (which == MODULUS) ? target->n : target->e;
  int out_len = BN_num_bytes(number);
  unsigned char *out = new unsigned char[out_len];

  out_len = BN_bn2bin(number, out); // Return value also indicates error.

  if (out_len < 0) {
    char *err = ERR_error_string(ERR_get_error(), NULL);
    Local<String> full_err = String::Concat(String::New("Get: "), String::New(err));
    Local<Value> exception = Exception::Error(full_err);
    return ThrowException(exception);
  }

  Local<Value> outString;
  if (out_len == 0) {
    outString = String::New("");
  } else {
    outString = Encode(out, out_len, BINARY);
  }

  if (out) free(out);
  return scope.Close(outString);
}

Handle<Value> RsaKeypair::GetModulus(const Arguments& args) {
  return GetBignum(args, MODULUS);
}

Handle<Value> RsaKeypair::GetExponent(const Arguments& args) {
  return GetBignum(args, EXPONENT);
}

Handle<Value> RsaKeypair::GetPadding(const Arguments& args) {
  HandleScope scope;

  RsaKeypair *kp = ObjectWrap::Unwrap<RsaKeypair>(args.Holder());

  Local<Value> outString;
  switch (kp->padding) {
    case RSA_PKCS1_OAEP_PADDING:
      outString = String::New("oaep");
      break;
    case RSA_PKCS1_PADDING:
      outString = String::New("pkcs1");
      break;
    case RSA_SSLV23_PADDING:
      outString = String::New("sslv23");
      break;
    case RSA_NO_PADDING:
      outString = String::New("none");
      break;
    default:
      Local<Value> exception = Exception::Error(String::New("No padding defined"));
      return ThrowException(exception);
  }
  return scope.Close(outString);
}

void RsaKeypair::AsyncWork(uv_work_t* req) {
  Baton* baton = static_cast<Baton*>(req->data);

  if (baton->mode == Baton::MODE_ENCRYPT) {
    int out_len = RSA_size(baton->keyPair->publicKey);
    unsigned char* out = (unsigned char*)malloc(out_len);
    
    uv_mutex_lock(&baton->keyPair->mutex);
    baton->r = RSA_public_encrypt(baton->len, baton->buf, out, baton->keyPair->publicKey, baton->keyPair->padding);
    uv_mutex_unlock(&baton->keyPair->mutex);

    baton->out = out;
    baton->out_len = out_len;
  }
  else if (baton->mode == Baton::MODE_DECRYPT) {
    int out_len = RSA_size(baton->keyPair->privateKey);
    unsigned char *out = (unsigned char*)malloc(out_len);

    uv_mutex_lock(&baton->keyPair->mutex);
    out_len = RSA_private_decrypt(baton->len, baton->buf, out, baton->keyPair->privateKey, baton->keyPair->padding);
    uv_mutex_unlock(&baton->keyPair->mutex);

    baton->out = out;
    baton->out_len = out_len;

    if (out_len < 0) {
      printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
    }
  }
  else {
    assert(false && "mode corrupted");
  }
}

void RsaKeypair::AsyncAfter(uv_work_t* req) {
  HandleScope scope;

  Baton* baton = static_cast<Baton*>(req->data);

  Local<Value> argv[2];

  if (baton->mode == Baton::MODE_ENCRYPT) {
    if (baton->r < 0) {
      char *err = ERR_error_string(ERR_get_error(), NULL);
      Local<String> full_err = String::Concat(String::New("RSA encrypt: "), String::New(err));
      Local<Value> exception = Exception::Error(full_err);
      argv[0] = exception;
      argv[1] = Local<Value>::New(Null());
    }
    else {
      Local<Value> outString;
      if (baton->out_len == 0) {
        outString = String::New("");
      }
      else {
        outString = Encode(baton->out, baton->out_len, BINARY);
      }

      argv[0] = Local<Value>::New(Null());
      argv[1] = outString;
    }

    // callback
    TryCatch try_catch;

    baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);

    if (try_catch.HasCaught()) {
      FatalException(try_catch);
    }

    if (baton->out) free(baton->out);
    delete[] baton->buf;
    baton->callback.Dispose();
    
    delete baton;
  }
  else if (baton->mode == Baton::MODE_DECRYPT) {
    if (baton->out_len < 0) {
      char *err = ERR_error_string(ERR_get_error(), NULL);
      Local<String> full_err = String::Concat(String::New("RSA decrypt: "), String::New(err));
      Local<Value> exception = Exception::Error(full_err);
      argv[0] = exception;
      argv[1] = Local<Value>::New(Null());
    }
    else {
      Local<Value> outString;
      if (baton->out_len == 0) {
        outString = String::New("");
      } 
      else {
        outString = Encode(baton->out, baton->out_len, baton->enc);
      }

      argv[0] = Local<Value>::New(Null());
      argv[1] = outString;
    }

    // callback
    TryCatch try_catch;

    baton->callback->Call(Context::GetCurrent()->Global(), 2, argv);

    if (try_catch.HasCaught()) {
      FatalException(try_catch);
    }

    if (baton->out) free(baton->out);
    delete[] baton->buf;
    baton->callback.Dispose();
    
    delete baton;
  }
  else {
    assert(false && "mode corrupted");
  }
}

// avoid link error...
enum encoding MyParseEncoding(Handle<Value> encoding_v, enum encoding _default) {
  HandleScope scope;

  if (!encoding_v->IsString()) return _default;

  String::Utf8Value encoding(encoding_v);

  if (strcasecmp(*encoding, "utf8") == 0) {
    return UTF8;
  } else if (strcasecmp(*encoding, "utf-8") == 0) {
    return UTF8;
  } else if (strcasecmp(*encoding, "ascii") == 0) {
    return ASCII;
  } else if (strcasecmp(*encoding, "base64") == 0) {
    return BASE64;
  } else if (strcasecmp(*encoding, "ucs2") == 0) {
    return UCS2;
  } else if (strcasecmp(*encoding, "ucs-2") == 0) {
    return UCS2;
  } else if (strcasecmp(*encoding, "binary") == 0) {
    return BINARY;
  } else if (strcasecmp(*encoding, "hex") == 0) {
    return HEX;
  } else if (strcasecmp(*encoding, "raw") == 0) {
    //if (!no_deprecation) {
    //  fprintf(stderr, "'raw' (array of integers) has been removed. "
    //                  "Use 'binary'.\n");
    //}
    return BINARY;
  } else if (strcasecmp(*encoding, "raws") == 0) {
    //if (!no_deprecation) {
    //  fprintf(stderr, "'raws' encoding has been renamed to 'binary'. "
    //                  "Please update your code.\n");
    //}
    return BINARY;
  } else {
    return _default;
  }
}

}  // namespace node

#if defined(_WIN32) || defined(_WIN64)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved ) {
  switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
      OpenSSL_add_all_algorithms();
      OpenSSL_add_all_ciphers();
      ERR_load_crypto_strings(); // for error log
      break;
  }

  return TRUE;
}
#else
void __attribute__ ((constructor)) mydlopen(void);
void
mydlopen(void) {
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
}
#endif

NODE_MODULE(node_rsa, node::RsaKeypair::Initialize);
