import { randomBytes } from 'crypto';
import type { IHookFunctions, IWebhookFunctions } from 'n8n-workflow';

import { CalendlyTrigger } from '../CalendlyTrigger.node';
import { verifySignature } from '../CalendlyTriggerHelpers';
import { calendlyApiRequest, getAuthenticationType } from '../GenericFunctions';

jest.mock('../GenericFunctions');
jest.mock('../CalendlyTriggerHelpers');
jest.mock('crypto', () => ({
	...jest.requireActual('crypto'),
	randomBytes: jest.fn(),
}));

describe('CalendlyTrigger', () => {
	let trigger: CalendlyTrigger;
	let mockHookFunctions: Pick<
		jest.Mocked<IHookFunctions>,
		'getNodeWebhookUrl' | 'getNodeParameter' | 'getWorkflowStaticData' | 'helpers'
	>;
	let mockWebhookFunctions: Pick<
		jest.Mocked<IWebhookFunctions>,
		'getBodyData' | 'getRequestObject' | 'getResponseObject' | 'getWorkflowStaticData' | 'helpers'
	>;

	beforeEach(() => {
		jest.clearAllMocks();
		trigger = new CalendlyTrigger();

		mockHookFunctions = {
			getNodeWebhookUrl: jest.fn(),
			getNodeParameter: jest.fn(),
			getWorkflowStaticData: jest.fn(),
			helpers: {} as any,
		};

		mockWebhookFunctions = {
			getBodyData: jest.fn(),
			getRequestObject: jest.fn(),
			getResponseObject: jest.fn(),
			getWorkflowStaticData: jest.fn(),
			helpers: {
				returnJsonArray: jest.fn((data) => data),
			} as any,
		};
	});

	describe('webhookMethods.default.create', () => {
		it('should generate a signing key and pass it to Calendly when using accessToken auth', async () => {
			const webhookUrl = 'https://example.com/webhook';
			const events = ['invitee.created'];
			const webhookSecret = 'a'.repeat(64);
			const userResource = {
				uri: 'https://api.calendly.com/users/USER',
				current_organization: 'https://api.calendly.com/organizations/ORG',
			};
			const responseData = {
				resource: { uri: 'https://api.calendly.com/webhook_subscriptions/SUB' },
			};

			(getAuthenticationType as jest.Mock).mockResolvedValue('accessToken');
			mockHookFunctions.getNodeWebhookUrl.mockReturnValue(webhookUrl);
			mockHookFunctions.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'events') return events;
				if (name === 'scope') return 'user';
				return undefined;
			});

			const webhookData: any = {};
			mockHookFunctions.getWorkflowStaticData.mockReturnValue(webhookData);

			(randomBytes as jest.Mock).mockReturnValue({
				toString: jest.fn().mockReturnValue(webhookSecret),
			});
			(calendlyApiRequest as jest.Mock)
				.mockResolvedValueOnce({ resource: userResource })
				.mockResolvedValueOnce(responseData);

			const result = await trigger.webhookMethods!.default.create.call(
				mockHookFunctions as unknown as IHookFunctions,
			);

			expect(result).toBe(true);
			expect(randomBytes).toHaveBeenCalledWith(32);
			expect(calendlyApiRequest).toHaveBeenLastCalledWith(
				'POST',
				'/webhook_subscriptions',
				expect.objectContaining({
					url: webhookUrl,
					events,
					organization: userResource.current_organization,
					scope: 'user',
					user: userResource.uri,
					signing_key: webhookSecret,
				}),
			);
			expect(webhookData.webhookURI).toBe(responseData.resource.uri);
			expect(webhookData.webhookSecret).toBe(webhookSecret);
		});

		it('should not generate a signing key when using legacy apiKey auth', async () => {
			const webhookUrl = 'https://example.com/webhook';
			const events = ['invitee.created'];

			(getAuthenticationType as jest.Mock).mockResolvedValue('apiKey');
			mockHookFunctions.getNodeWebhookUrl.mockReturnValue(webhookUrl);
			mockHookFunctions.getNodeParameter.mockImplementation((name: string) => {
				if (name === 'events') return events;
				return undefined;
			});

			const webhookData: any = {};
			mockHookFunctions.getWorkflowStaticData.mockReturnValue(webhookData);

			(calendlyApiRequest as jest.Mock).mockResolvedValue({ id: 'webhook-id' });

			const result = await trigger.webhookMethods!.default.create.call(
				mockHookFunctions as unknown as IHookFunctions,
			);

			expect(result).toBe(true);
			expect(randomBytes).not.toHaveBeenCalled();
			expect(calendlyApiRequest).toHaveBeenCalledWith('POST', '/hooks', {
				url: webhookUrl,
				events,
			});
			expect(webhookData.webhookSecret).toBeUndefined();
		});
	});

	describe('webhookMethods.default.delete', () => {
		it('should clean up the signing key when deleting an accessToken webhook', async () => {
			const webhookData: any = {
				webhookURI: 'https://api.calendly.com/webhook_subscriptions/SUB',
				webhookSecret: 'stored-secret',
			};

			(getAuthenticationType as jest.Mock).mockResolvedValue('accessToken');
			mockHookFunctions.getWorkflowStaticData.mockReturnValue(webhookData);
			(calendlyApiRequest as jest.Mock).mockResolvedValue({});

			const result = await trigger.webhookMethods!.default.delete.call(
				mockHookFunctions as unknown as IHookFunctions,
			);

			expect(result).toBe(true);
			expect(webhookData.webhookURI).toBeUndefined();
			expect(webhookData.webhookSecret).toBeUndefined();
		});
	});

	describe('webhook', () => {
		it('should return 401 when signature verification fails', async () => {
			const mockResponse = {
				status: jest.fn().mockReturnThis(),
				send: jest.fn().mockReturnThis(),
				end: jest.fn(),
			};

			(verifySignature as jest.Mock).mockReturnValue(false);
			mockWebhookFunctions.getResponseObject.mockReturnValue(mockResponse as any);

			const result = await trigger.webhook.call(
				mockWebhookFunctions as unknown as IWebhookFunctions,
			);

			expect(verifySignature).toHaveBeenCalled();
			expect(mockResponse.status).toHaveBeenCalledWith(401);
			expect(mockResponse.send).toHaveBeenCalledWith('Unauthorized');
			expect(mockResponse.end).toHaveBeenCalled();
			expect(result).toEqual({ noWebhookResponse: true });
			expect(mockWebhookFunctions.getBodyData).not.toHaveBeenCalled();
		});

		it('should process the webhook when signature verification passes', async () => {
			const bodyData = { event: 'invitee.created', payload: { foo: 'bar' } };

			(verifySignature as jest.Mock).mockReturnValue(true);
			mockWebhookFunctions.getBodyData.mockReturnValue(bodyData as any);

			const result = await trigger.webhook.call(
				mockWebhookFunctions as unknown as IWebhookFunctions,
			);

			expect(verifySignature).toHaveBeenCalled();
			expect(result).toEqual({ workflowData: [bodyData] });
		});

		it('should process the webhook when no secret is configured (backward compatibility)', async () => {
			const bodyData = { event: 'invitee.created' };

			(verifySignature as jest.Mock).mockReturnValue(true);
			mockWebhookFunctions.getBodyData.mockReturnValue(bodyData as any);

			const result = await trigger.webhook.call(
				mockWebhookFunctions as unknown as IWebhookFunctions,
			);

			expect(verifySignature).toHaveBeenCalled();
			expect(result.workflowData).toBeDefined();
		});
	});
});
