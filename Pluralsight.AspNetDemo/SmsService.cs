using System.Configuration;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Twilio;
using Twilio.Rest.Api.V2010.Account;
using Twilio.Types;

namespace Pluralsight.AspNetDemo
{
    public class SmsService : IIdentityMessageService
    {
        public async Task SendAsync(IdentityMessage message)
        {
            var sid = ConfigurationManager.AppSettings["twilio:Sid"];
            var token = ConfigurationManager.AppSettings["twilio:Token"];
            var from = ConfigurationManager.AppSettings["twilio:From"];

            TwilioClient.Init(sid, token);
            await MessageResource.CreateAsync(new PhoneNumber(message.Destination), from: new PhoneNumber(from), body: message.Body);
        }
    }
}