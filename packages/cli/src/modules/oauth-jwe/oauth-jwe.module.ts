import type { ModuleInterface } from '@n8n/decorators';
import { BackendModule } from '@n8n/decorators';
import { Container } from '@n8n/di';

import { OAuthJweServiceProxy } from '@/oauth/oauth-jwe-service.proxy';

@BackendModule({ name: 'oauth-jwe', instanceTypes: ['main'] })
export class OAuthJweModule implements ModuleInterface {
	async init() {
		const { OAuthJweKeyService } = await import('./oauth-jwe-key.service');
		await Container.get(OAuthJweKeyService).initialize();

		const { OAuthJweDecryptService } = await import('./oauth-jwe-decrypt.service');
		Container.get(OAuthJweServiceProxy).setHandler(Container.get(OAuthJweDecryptService));

		// Temporary dev-only JWKS endpoint, removed when IAM-478 ships.
		await import('./oauth-jwe.controller');
	}

	async context() {
		return { oauthJweProxyProvider: Container.get(OAuthJweServiceProxy) };
	}
}
