import { Get, RestController } from '@n8n/decorators';
import type { JWK } from 'jose';

import { OAuthJweKeyService } from './oauth-jwe-key.service';

/**
 * Temporary dev/test endpoint for fetching the instance OAuth2 JWE public
 * keys. Will be removed once the proper JWKS URI ships in IAM-478. Kept
 * unauthenticated so an IdP can fetch it directly during local testing.
 */
@RestController('/oauth-jwe')
export class OAuthJweController {
	constructor(private readonly keyService: OAuthJweKeyService) {}

	@Get('/jwks', { skipAuth: true })
	async getJwks(): Promise<{ keys: JWK[] }> {
		const keys = await this.keyService.getPublicJwks();
		return { keys };
	}
}
