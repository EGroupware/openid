<?php
/**
 * EGroupware OpenID Connect / OAuth2 server: /jwks contract test
 *
 * @link https://www.egroupware.org
 * @author Ralf Becker <rb-At-egroupware.org>
 * @package openid
 * @license http://opensource.org/licenses/gpl-license.php GPL - GNU General Public License
 */

namespace EGroupware\OpenID\Tests;

require_once __DIR__.'/OpenIDTestBase.php';

/**
 * GET /jwks
 *
 * Contract under test: the published JSON Web Key Set contains a valid RS256 public key that
 * actually verifies the signature of real access-tokens issued by this server. Note: the current
 * implementation does NOT put a "kid" in issued JWTs' headers (only one key is ever published, so
 * relying parties don't need one to pick the right key) - so this is tested via real signature
 * verification against the JWK's n/e, not kid-matching. Pass criteria: HTTP 200, well-formed JWK
 * (kty=RSA, n/e present), and openssl_verify() succeeding against a real access_token's signature.
 */
class JwksTest extends OpenIDTestBase
{
	protected static array $test_grants = ['client_credentials'];

	public function testJwksShape() : void
	{
		$response = $this->httpClient()->get($this->endpointUrl('/jwks'));
		$this->assertHttpStatus(200, $response);

		$data = $this->jsonDecode($response);
		$this->assertNotEmpty($data['keys'] ?? null, 'keys array missing/empty');
		$key = $data['keys'][0];
		$this->assertSame('RSA', $key['kty'] ?? null);
		$this->assertSame('sig', $key['use'] ?? null);
		$this->assertSame('RS256', $key['alg'] ?? null);
		$this->assertNotEmpty($key['n'] ?? null, 'modulus (n) missing');
		$this->assertNotEmpty($key['e'] ?? null, 'exponent (e) missing');
		$this->assertNotEmpty($key['kid'] ?? null, 'kid missing');
	}

	/**
	 * Reconstruct a PEM RSA public key from a JWK's base64url-encoded modulus (n) / exponent (e),
	 * so we can verify a real access-token's signature against exactly what /jwks publishes -
	 * without reading any private/public key file directly (that would defeat the point of a
	 * black-box HTTP contract test). Standard RSA JWK -> DER SubjectPublicKeyInfo encoding.
	 */
	protected function jwkToPem(array $jwk) : string
	{
		$b64url_decode = static fn(string $s) => base64_decode(strtr($s, '-_', '+/').str_repeat('=', (4 - strlen($s) % 4) % 4));
		$der_len = static function(int $len) {
			if ($len < 128) return chr($len);
			$bytes = ltrim(pack('N', $len), "\x00");
			return chr(0x80 | strlen($bytes)).$bytes;
		};
		$der_int = static function(string $bin) use ($der_len) {
			if (ord($bin[0]) > 0x7f) $bin = "\x00".$bin;
			return "\x02".$der_len(strlen($bin)).$bin;
		};

		$modulus = $der_int($b64url_decode($jwk['n']));
		$exponent = $der_int($b64url_decode($jwk['e']));
		$rsaPublicKey = "\x30".$der_len(strlen($modulus.$exponent)).$modulus.$exponent;

		// wrap in SubjectPublicKeyInfo with the rsaEncryption OID
		$algId = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$bitString = "\x03".$der_len(strlen($rsaPublicKey) + 1)."\x00".$rsaPublicKey;
		$spki = "\x30".$der_len(strlen($algId.$bitString)).$algId.$bitString;

		return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($spki), 64)."-----END PUBLIC KEY-----\n";
	}

	public function testAccessTokenSignatureVerifiesAgainstJwks() : void
	{
		$response = $this->httpClient()->get($this->endpointUrl('/jwks'));
		$this->assertHttpStatus(200, $response);
		$keys = $this->jsonDecode($response)['keys'] ?? [];
		$this->assertNotEmpty($keys);
		$pem = $this->jwkToPem($keys[0]);

		$token = $this->getClientCredentialsToken();
		$parts = explode('.', $token['access_token']);
		$this->assertCount(3, $parts, 'access_token is not a JWT (3 dot-separated parts)');
		[$header_b64, $payload_b64, $signature_b64] = $parts;
		$signature = base64_decode(strtr($signature_b64, '-_', '+/'));

		$ok = openssl_verify($header_b64.'.'.$payload_b64, $signature, $pem, OPENSSL_ALGO_SHA256);
		$this->assertSame(1, $ok, 'access_token JWT signature must verify against the public key published at /jwks');
	}
}
