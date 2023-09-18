#include "hblk_crypto.h"

/**
 * sha256 - Compute the hash of a sequence of bytes
 *
 * @s: is the sequence of bytes to be hashed
 * @len: is the number of bytes to hash in s
 * @digest: The destination of the sequence hashed
 *
 * Return: Return a pointer to digest, NULL if digets happens to be NULL
*/
uint8_t *sha256(int8_t const *s, size_t len,
				uint8_t digest[SHA256_DIGEST_LENGTH])
{

	if (!digest)
		return (NULL);

	return (SHA256((uint8_t *)s, len, digest));
}
