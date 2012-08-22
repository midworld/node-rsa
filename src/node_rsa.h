#include <node.h>
#include <node_object_wrap.h>
#include <v8.h>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

namespace node {

enum WhichComponent {
  MODULUS, EXPONENT
};

class RsaKeypair : ObjectWrap {
 public:
  static void Initialize(v8::Handle<v8::Object> target);

 protected:
  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPrivateKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPublicKey(const v8::Arguments& args);
  static v8::Handle<v8::Value> SetPadding(const v8::Arguments& args);
  static v8::Handle<v8::Value> EncryptSync(const v8::Arguments& args);
  static v8::Handle<v8::Value> DecryptSync(const v8::Arguments& args);
  static v8::Handle<v8::Value> Encrypt(const v8::Arguments& args);
  static v8::Handle<v8::Value> Decrypt(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetModulus(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetExponent(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetPadding(const v8::Arguments& args);

  // Helper for GetModulus() and GetExponent().
  static v8::Handle<v8::Value> GetBignum(const v8::Arguments& args, WhichComponent which);

  RsaKeypair() : ObjectWrap() {
  }

  ~RsaKeypair() {
    if (publicKey != NULL) RSA_free(publicKey);
    if (privateKey != NULL) RSA_free(privateKey);
  }

 private:
  RSA* publicKey;
  RSA* privateKey;
  int padding;

  struct Baton {
    uv_work_t reqeust;
    v8::Persistent<v8::Function> callback;

    RSA* key;
    int padding;

    unsigned char* buf;
    ssize_t len;
    enum { MODE_ENCRYPT, MODE_DECRYPT } mode;
    enum encoding enc;

    int r;
    unsigned char* out;
    int out_len;
  };

  static void AsyncWork(uv_work_t* req);
  static void AsyncAfter(uv_work_t* req);
};

enum encoding MyParseEncoding(v8::Handle<v8::Value> encoding_v,
                              enum encoding _default = BINARY);

} // namespace node
