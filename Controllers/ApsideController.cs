using Apside_2.Models;
using System;  
using System.Net;
using System.Net.Http;
using System.Web.Http; 
using System.Security.Cryptography;
using System.Globalization; 
using System.Text;
using Apside_2.Helpers;

namespace Apside_2.Controllers
{
    [RoutePrefix("api")]
    public class ApsideController : ApiController
    {
        // Person constants (mail, pwd and access_key)
        const string CORRECT_MAIL = "pserou@gmailcom";
        const string CORRECT_PWD = "pserou";
        const string ACCESS_KEY = "YOUR_ACCESS_KEY"; //          PLEASE REPLACE BY YOUR AWS ACCESS_KEY TO TEST THE CODE

        readonly Person PERSON = new Person {
                                                email = CORRECT_MAIL,
                                                password = CORRECT_PWD,
                                                accessKey = ACCESS_KEY
                                            };
        // Header constants
        const string AUTHORIZATION = "authorization";
        const string X_AMZ_DATE = "x-amz-date";
        const string CONTENT_MD5 = "Content-MD5";
        const string CONTENT_TYPE = "Content-Type";
        const string DUMMY_URL_AWS = "/johnsmith/photos/puppy.jpg"; 

        [HttpPost]
        [Route("authenticate")]
        public HttpResponseMessage Authenticate([FromBody] Person p)
        {
            bool result = (
                            p != null && !string.IsNullOrEmpty(p.email) && !string.IsNullOrEmpty(p.password) &&
                            p.email.Equals(PERSON.email) &&
                            p.password.Equals(PERSON.password)
                           );

            return Request.CreateResponse(HttpStatusCode.OK, result);
        } 
 
        [HttpGet]
        [Route("confidentials/{email}")]
        public HttpResponseMessage AuthentifyByEmail(string email)
        {
            string access_key_by_email = string.Empty;

            if (email != null && email.Split('=')[1].Equals(PERSON.email))
                access_key_by_email = ACCESS_KEY;

            if (Request.GetHeader(AUTHORIZATION) != null && Request.GetHeader(AUTHORIZATION).StartsWith("AWS "))
            {
                // Get signature from Request
                string signatureFromRequest = Request.GetHeader(AUTHORIZATION).Split(':')[1];

                if (!string.IsNullOrEmpty(signatureFromRequest))
                {
                    // Furthermore, the client timestamp included with an authenticated request 
                    //              must be within 15 minutes of the Amazon S3 system time when the request is received
                    DateTime clientTimestamp;
                    bool a = DateTime.TryParseExact(Request.GetHeader(X_AMZ_DATE), "R", DateTimeFormatInfo.CurrentInfo, DateTimeStyles.AdjustToUniversal, out clientTimestamp);
                    bool delta_inf_15mn = Math.Abs((clientTimestamp - DateTime.UtcNow).TotalMinutes) <= 15;

                    if (Request.GetHeader(X_AMZ_DATE) != null && delta_inf_15mn)
                    {
                        var signatureComputed = GetSignature(Request, access_key_by_email);

                        if (signatureComputed.Equals(signatureFromRequest))
                        {
                            return Request.CreateResponse(HttpStatusCode.OK, true);
                        }
                    }
                }
            }

            return Request.CreateResponse(HttpStatusCode.Unauthorized, false);
        }

        /// <summary>
        /// The Amazon S3 REST API uses a custom HTTP scheme based on a keyed-HMAC (Hash Message Authentication Code) for authentication. 
        /// To authenticate a request, you first concatenate selected elements of the request to form a string. 
        /// You then use your AWS secret access key to calculate the HMAC of that string
        /// </summary>
        /// <param name="request"></param>
        /// <param name="accessKey"></param>
        /// <returns>computed signature</returns>
        private string GetSignature(HttpRequestMessage request, string accessKey)
        {
            var utf8Encoding = new UTF8Encoding();            
            var stringToSign = String.Format(
                                                "{0}\n{1}\n{2}\n{3}\n{4}",
                                                request.Method,
                                                request.GetHeader(CONTENT_MD5) ?? "",
                                                request.GetHeader(CONTENT_TYPE) ?? "",
                                                request.GetHeader(X_AMZ_DATE) ?? "",
                                                DUMMY_URL_AWS
                                            );

            var hmacSha1 = new HMACSHA1(utf8Encoding.GetBytes(accessKey));

            return Convert.ToBase64String(hmacSha1.ComputeHash(utf8Encoding.GetBytes(stringToSign)));
        }



        #region pour tester, activer cette méthode qui permet de calculer la Signature en fonction du  -15 mn < timestamp < +15 mn
        /*
        [HttpGet]
        [Route("confidentials/{email}")]
        public HttpResponseMessage CalculateSignature(string email)
        {
            var access_key_by_email = email != null && email.Split('=')[1].Equals(PERSON.email) ? ACCESS_KEY : string.Empty;



        // GET /photos/puppy.jpg HTTP/1.1
        // Authorization: AWS YOUR_ACCESS_KEY:j8E8/YAJG9DjvL5dz237jeiE0ho="   CECI N'EST VALABLE QUE POUR "Fri, 09 Nov 2018 16:00:24 GMT" 
        // Authorization: AWS YOUR_ACCESS_KEY:UTSLdLgPtoKLRJL80/NbxjoIGJg="   CECI N'EST VALABLE QUE POUR "Fri, 09 Nov 2018 16:28:24 GMT"
        //                                         t3u0/m/rNRcH1J9oz3NQZ3KnG6M=                                             16:58:24

        string timestamp = "Fri, 09 Nov 2018 16:58:24 GMT";// String.Format("{0:r}", DateTime.UtcNow);
            var request = new HttpRequestMessage(HttpMethod.Get, "/photos/puppy.jpg");
            request.Headers.Add("Authorization", "AWS YOUR_ACCESS_KEY:t3u0/m/rNRcH1J9oz3NQZ3KnG6M=");
            request.Headers.Add("X-Amz-Date", timestamp);


            var stringToSign = String.Format(
                                                "{0}\n{1}\n{2}\n{3}\n{4}",
                                                request.Method,
                                                request.GetHeader(CONTENT_MD5) ?? "",
                                                request.GetHeader(CONTENT_TYPE) ?? "",
                                                request.GetHeader(X_AMZ_DATE) ?? "",
                                                DUMMY_URL_AWS
                                            );
                                        
            var utf8Encoding = new UTF8Encoding();
            var hmacSha1 = new HMACSHA1(utf8Encoding.GetBytes(access_key_by_email));

            // Base64(HMAC-SHA1(YourSecretAccessKeyID, UTF-8-Encoding-Of(StringToSign)));
            string signatureComputed = Convert.ToBase64String(hmacSha1.ComputeHash(utf8Encoding.GetBytes(stringToSign)));
            string signatureFromRequest = request.GetHeader("Authorization").Split(':')[1];

            if (signatureComputed == signatureFromRequest)
            {
                return Request.CreateResponse(HttpStatusCode.OK, true);
            }

            return Request.CreateResponse(HttpStatusCode.Unauthorized, false);
        }
        */
        #endregion

    }
}


