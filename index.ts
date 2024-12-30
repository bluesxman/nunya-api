import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { S3 } from 'aws-sdk';
import * as crypto from 'crypto';

const s3 = new S3();
const BUCKET_NAME = process.env.STORAGE_BUCKET_NAME;
const EXPIRATION_HOURS = 24;

interface UploadRequest {
    encryptedData: string;
    iv: string;
    encryptedSymmetricKey: string;
    fileName: string;
    recipientPublicKey: string;
}

export const handler = async (
    event: APIGatewayProxyEvent
): Promise<APIGatewayProxyResult> => {
    try {
        switch (event.httpMethod) {
            case 'POST':
                if (event.path === '/upload') {
                    return handleUpload(event);
                }
                if (event.path === '/download') {
                    return handleDownload(event);
                }
                break;
            case 'GET':
                if (event.path === '/challenge') {
                    return generateChallenge(event);
                }
                break;
        }

        return {
            statusCode: 404,
            body: JSON.stringify({ message: 'Not Found' })
        };
    } catch (error) {
        console.error('Error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ message: 'Internal Server Error' })
        };
    }
};

async function handleUpload(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
    const uploadRequest: UploadRequest = JSON.parse(event.body || '{}');
    const fileId = crypto.randomBytes(16).toString('hex');

    // Store encrypted file data
    await s3.putObject({
        Bucket: BUCKET_NAME!,
        Key: `files/${fileId}/data`,
        Body: Buffer.from(uploadRequest.encryptedData, 'base64'),
        Metadata: {
            iv: uploadRequest.iv,
            fileName: uploadRequest.fileName,
            recipientPublicKey: uploadRequest.recipientPublicKey,
            expirationTime: (Date.now() + EXPIRATION_HOURS * 3600 * 1000).toString()
        }
    }).promise();

    // Store encrypted symmetric key separately
    await s3.putObject({
        Bucket: BUCKET_NAME!,
        Key: `files/${fileId}/key`,
        Body: Buffer.from(uploadRequest.encryptedSymmetricKey, 'base64')
    }).promise();

    return {
        statusCode: 200,
        body: JSON.stringify({
            downloadUrl: `https://nunya.smackwerks.com/download/${fileId}`
        })
    };
}

async function generateChallenge(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
    const fileId = event.queryStringParameters?.fileId;

    if (!fileId) {
        return {
            statusCode: 400,
            body: JSON.stringify({ message: 'Missing fileId' })
        };
    }

    const challenge = crypto.randomBytes(32).toString('base64');

    // Store challenge temporarily
    await s3.putObject({
        Bucket: BUCKET_NAME!,
        Key: `challenges/${fileId}`,
        Body: challenge,
        Expires: new Date(Date.now() + 300000) // 5 minute expiration
    }).promise();

    return {
        statusCode: 200,
        body: JSON.stringify({ challenge })
    };
}

async function handleDownload(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
    const { fileId, signature } = JSON.parse(event.body || '{}');

    // Verify challenge signature
    const challengeResponse = await s3.getObject({
        Bucket: BUCKET_NAME!,
        Key: `challenges/${fileId}`
    }).promise();

    const challenge = challengeResponse.Body?.toString();

    // Get file metadata
    const fileMetadata = await s3.getObject({
        Bucket: BUCKET_NAME!,
        Key: `files/${fileId}/data`
    }).promise();

    const publicKey = fileMetadata.Metadata?.recipientPublicKey;

    // Verify signature using public key
    const verify = crypto.createVerify('SHA256');
    verify.update(challenge || '');

    if (!verify.verify(publicKey!, signature)) {
        return {
            statusCode: 403,
            body: JSON.stringify({ message: 'Invalid signature' })
        };
    }

    // Generate pre-signed URLs for download
    const dataUrl = s3.getSignedUrl('getObject', {
        Bucket: BUCKET_NAME!,
        Key: `files/${fileId}/data`,
        Expires: 300 // 5 minutes
    });

    const keyUrl = s3.getSignedUrl('getObject', {
        Bucket: BUCKET_NAME!,
        Key: `files/${fileId}/key`,
        Expires: 300
    });

    return {
        statusCode: 200,
        body: JSON.stringify({
            dataUrl,
            keyUrl,
            iv: fileMetadata.Metadata?.iv,
            fileName: fileMetadata.Metadata?.fileName
        })
    };
}