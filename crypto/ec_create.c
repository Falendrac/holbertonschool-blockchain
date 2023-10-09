#include "hblk_crypto.h"
#include "stdio.h"

/**
 * ec_create - creates a new EC key pair with the elliptic curve
 * secp256k1 and generates public and private key
 *
 * Return: A pointer to an EC_KEY structure, containing both the public
 * and private keys, or NULL upon faillure
*/
EC_KEY *ec_create(void)
{
	EC_KEY *newKeyPair;

	newKeyPair = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!newKeyPair)
		return (NULL);

	EC_KEY_generate_key(newKeyPair);

	return (newKeyPair);
}
