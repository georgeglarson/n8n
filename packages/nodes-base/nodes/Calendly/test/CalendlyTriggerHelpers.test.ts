import { createHmac } from 'crypto';

import { verifySignature } from '../CalendlyTriggerHelpers';

describe('CalendlyTriggerHelpers', () => {
	let mockWebhookFunctions: any;
	const testSecret = 'test-secret-key-12345';
	const testPayload = Buffer.from('{"event":"invitee.created"}');

	function buildSignatureHeader(secret: string, timestamp: number, payload: Buffer) {
		const hmac = createHmac('sha256', secret);
		hmac.update(`${timestamp}.`);
		hmac.update(payload);
		return `t=${timestamp},v1=${hmac.digest('hex')}`;
	}

	beforeEach(() => {
		jest.clearAllMocks();

		mockWebhookFunctions = {
			getRequestObject: jest.fn(),
			getWorkflowStaticData: jest.fn(),
		};
	});

	describe('verifySignature', () => {
		it('should return true when no secret is configured (backward compatibility)', () => {
			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue(null),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(true);
		});

		it('should return true when signature and timestamp are valid', () => {
			const timestamp = Math.floor(Date.now() / 1000);
			const headerValue = buildSignatureHeader(testSecret, timestamp, testPayload);

			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockImplementation((name) => {
					if (name === 'calendly-webhook-signature') return headerValue;
					return null;
				}),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(true);
		});

		it('should return false when signature does not match', () => {
			const timestamp = Math.floor(Date.now() / 1000);
			const headerValue = `t=${timestamp},v1=invalidsignature`;

			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockImplementation((name) => {
					if (name === 'calendly-webhook-signature') return headerValue;
					return null;
				}),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(false);
		});

		it('should return false when signature was computed with a different secret', () => {
			const timestamp = Math.floor(Date.now() / 1000);
			const headerValue = buildSignatureHeader('different-secret', timestamp, testPayload);

			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue(headerValue),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(false);
		});

		it('should return false when signature header is missing', () => {
			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue(null),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(false);
		});

		it('should return false when timestamp is too old', () => {
			const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 minutes ago
			const headerValue = buildSignatureHeader(testSecret, oldTimestamp, testPayload);

			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue(headerValue),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(false);
		});

		it('should return false when header is malformed', () => {
			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue('not-a-valid-header'),
				rawBody: testPayload,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(false);
		});

		it('should return false when raw body is missing', () => {
			const timestamp = Math.floor(Date.now() / 1000);
			const headerValue = buildSignatureHeader(testSecret, timestamp, testPayload);

			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue(headerValue),
				rawBody: undefined,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(false);
		});

		it('should accept raw body provided as a string', () => {
			const timestamp = Math.floor(Date.now() / 1000);
			const stringBody = '{"event":"invitee.created"}';
			const headerValue = buildSignatureHeader(testSecret, timestamp, Buffer.from(stringBody));

			mockWebhookFunctions.getWorkflowStaticData.mockReturnValue({
				webhookSecret: testSecret,
			});
			mockWebhookFunctions.getRequestObject.mockReturnValue({
				header: jest.fn().mockReturnValue(headerValue),
				rawBody: stringBody,
			});

			const result = verifySignature.call(mockWebhookFunctions);

			expect(result).toBe(true);
		});
	});
});
