#include "hblk_crypto.h"

/**
 * ec_sign - Sign a given set of bytes, using a given EC_KEY private key
 *
 * @key: The EC_KEY pair containing the private key
 * @msg: Points to the msglen characters to be signed
 * @msglen: Number of characters in msg
 * @sig: The adress at whichi to store the signature
 *
 * Return: A pointer to the signature buffer upon succes, NULL if faillure
*/
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg,
				size_t msglen, sig_t *sig)
{
	unsigned int sigLen = 0;

	if (!key || !msg)
		return (NULL);

	if (!ECDSA_sign(0, msg, msglen, sig->sig, &sigLen, (EC_KEY *)key))
		return (NULL);

	sig->len = (uint8_t)sigLen;

	return (sig->sig);
}
