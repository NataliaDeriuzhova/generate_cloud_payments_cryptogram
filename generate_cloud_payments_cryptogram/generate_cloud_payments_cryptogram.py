from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArBZ1NNjvszen6BNWsgyDUJvDUZDtvR4jKNQtEwW1iW7hqJr0TdD8hgTxw3DfH+Hi/7ZjSNdH5EfChvgVW9wtTxrvUXCOyJndReq7qNMo94lHpoSIVW82dp4rcDB4kU+q+ekh5rj9Oj6EReCTuXr3foLLBVpH0/z1vtgcCfQzsLlGkSTwgLqASTUsuzfI8viVUbxE1a+600hN0uBh/CYKoMnCp/EhxV8g7eUmNsWjZyiUrV8AA/5DgZUCB+jqGQT/Dhc8e21tAkQ3qan/jQ5i/QYocA/4jW3WQAldMLj0PA36kINEbuDKq8qRh25v+k4qyjb7Xp4W2DywmNtG3Q20MQIDAQAB";
KEY_VERSION = "04"


def generate_cloud_payments_cryptogram(card_number, card_exp, card_cvv, public_id):
    short_number = card_number[0:6] + card_number[len(card_number) - 4:len(card_number)]
    exp = card_exp[2:4] + card_exp[0:2]
    s = card_number + "@" + exp + "@" + card_cvv + "@" + public_id
    secret_string = bytes(s, "ASCII")
    key = b64decode(PUBLIC_KEY)
    key = RSA.importKey(key)

    cipher = PKCS1_OAEP.new(key)  # RSA/ECB/OAEPWithSHA1AndMGF1Padding
    crypto = b64encode(cipher.encrypt(secret_string))
    crypto64 = "02" + short_number + exp + KEY_VERSION + crypto.decode("utf-8")
    cr_array = crypto64.split('\\n')
    crypto64 = ""
    for i in range(len(cr_array)):
        crypto64 += cr_array[i]
    return crypto64
