#include "hblk_crypto.h"

/**
 * ec_verify - Verifies the signature of a given set of bytes, using a given
 * EC_KEY public key
 *
 * @key: The EC_KEY pair with the public key
 * @msg: Points to the msglen characters to verify the signature of
 * @msglen: The number of characters in the msg
 * @sig: points to the signature to be checked
 *
 * Return: 1 if the signature is valid, 0 otherwise or on faillure
*/
int ec_verify(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t const *sig)
{

	if (!key || !msg || !sig)
		return (0);

	if (ECDSA_verify(0, msg, msglen, sig->sig, sig->len, (EC_KEY *)key) == 1)
		return (1);

	return (0);
}
