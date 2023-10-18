#include "hblk_crypto.h"

/**
 * ec_from_pub - Create an EC_KEY structure given a public key
 *
 * @pub: contains the pubic key to be converted
 *
 * Return: an EC_KEY structure, NULL if faillure
*/
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN])
{
	EC_KEY *newECKey = NULL;
	EC_POINT *newPoint = NULL;
	const EC_GROUP *newGroup = NULL;

	newECKey = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!newECKey)
		return (NULL);

	newGroup = EC_KEY_get0_group(newECKey);
	newPoint = EC_POINT_new(newGroup);
	if (!newPoint)
	{
		EC_KEY_free(newECKey);
		return (NULL);
	}

	if (!EC_POINT_oct2point(newGroup, newPoint, pub, EC_PUB_LEN, NULL) ||
		!EC_KEY_set_public_key(newECKey, newPoint))
	{
		EC_KEY_free(newECKey);
		EC_POINT_free(newPoint);
		return (NULL);
	}
	EC_POINT_free(newPoint);
	return (newECKey);
}
