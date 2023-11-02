#include "hblk_crypto.h"

uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t *sig)
{
	unsigned int sigLen = 0;

	if (!key || !msg)
		return (NULL);

	if (!ECDSA_sign(0, msg, msglen, sig->sig, &sigLen, (EC_KEY *)key))
		return (NULL);

	sig->len = (uint8_t)sigLen;

	return (sig->sig);
}
