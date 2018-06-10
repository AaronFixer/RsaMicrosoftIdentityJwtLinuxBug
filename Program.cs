using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;

namespace AuthBugSample
{
    class Program
    {
        static void Main(string[] args)
		{
			var issueTime = DateTime.Now;

			var claims = new List<Claim>
			{
				new Claim(JwtRegisteredClaimNames.Sub, "1234567890"),
				new Claim(JwtRegisteredClaimNames.Jti, issueTime.ToString()),
				new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.Now).ToString(), ClaimValueTypes.Integer64),
				new Claim(ClaimTypes.Name, "Sample user"),
				new Claim(ClaimTypes.Role, "User")
			};

			SigningCredentials signingCredentials = null;
			using (RSA privateRsa = RSA.Create())
			{
				var privateKeyXml = File.ReadAllText("rsa-private-key.xml");
				privateRsa.FromXmlStringCore(privateKeyXml);
				var privateKey = new RsaSecurityKey(privateRsa);
				signingCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.RsaSha256);
			}

			var jwt = new JwtSecurityToken(
				issuer: "Sample Issuer",
				audience: "Sample Audience",
				claims: claims,
				notBefore: issueTime,
				expires: issueTime.Add(TimeSpan.FromMinutes(120)), 
				signingCredentials: signingCredentials
				);

			var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
			Console.WriteLine("Token generated.");
			Console.WriteLine(encodedJwt);
			Console.WriteLine("Press Enter to close app...");
			Console.ReadLine();
		}

		private static long ToUnixEpochDate(DateTime date)
			=> (long)Math.Round((date.ToUniversalTime() -
				new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
				.TotalSeconds);
	}
}
