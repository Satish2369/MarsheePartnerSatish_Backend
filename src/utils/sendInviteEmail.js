const { SESv2Client, SendEmailCommand } = require('@aws-sdk/client-sesv2');

const FRONTEND_URL ='https://marsheepartnersatish.vercel.app';


const sesClient = new SESv2Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.ACCESS_KEY,
    secretAccessKey: process.env.SECRET_ACCESS_KEY
  }
});

const sendInviteEmail = async ({ toEmail, name, role, token }) => {
  try {
    const setupUrl = `${FRONTEND_URL}/setup-partner?token=${token}&email=${toEmail}`;

    const command = new SendEmailCommand({
      FromEmailAddress: process.env.SES_VERIFIED_EMAIL,
      Destination: {
        ToAddresses: [toEmail],
      },
      Content: {
        Simple: {
          Subject: {
            Data: `Invitation to join Marshee as ${role}`,
          },
          Body: {
            Html: {
              Data: `
                <h1>Welcome to marshee!</h1>
                <p>Hello ${name},</p>
                <p>You have been invited to join marshee as a <strong>${role}</strong>.</p>
                <p>Please click the link below to set up your account:</p>
                <a href="${setupUrl}">Set up your account</a>
                <p>This link will expire in 5 days.</p>
              `,
            },
            
            Text: {
              Data: `Hello ${name}, please visit ${setupUrl} to complete setup.`,
            },
          },
        },
      }
    });

    await sesClient.send(command);

    return { success: true };
  } catch (error) {
    console.error('AWS SES SDK Email Error:', error);
    return { success: false, error: error.message };
  }
};

module.exports = sendInviteEmail;
