using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Core.GenericResultModel;
using Domain.Helpers;
using Infrastructure;
using MediatR;
using Novell.Directory.Ldap;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Dapper;



// ldapusername in usertable
//ldarole in role
namespace Application.Auth.LoginWithMobile.Command
{
    public class LoginLDAPCommand : IRequest<ApiResult<LoginDto>>
    {

        private string user;
        [Required]
        public string User
        {
            get { return user; }
            set { user = value; }
        }

        private string pass;
        [Required]
        public string Pass
        {
            get { return pass; }
            set { pass = value; }
        }





        public class LoginLDAPCommandHandler : IRequestHandler<LoginLDAPCommand, ApiResult<LoginDto>>
        {
            private readonly IUnitOfWork _unitOfWork;
            private readonly IMediator _mediator;
            private readonly IConfiguration _config;

            public LoginLDAPCommandHandler(IUnitOfWork unitOfWork, IMediator mediator, IConfiguration configuration)
            {
                _unitOfWork = unitOfWork;
                _mediator = mediator;
                _config = configuration;
            }

            public async Task<ApiResult<LoginDto>> Handle(LoginLDAPCommand request, CancellationToken cancellationToken)
            {

                if (request.User == null)
                    return new ApiResult<LoginDto>() { StatusCode = EStatusCode.BadRequest, ErrorCode = 437 };

                var service = new List<string>();
                bool secondLdapCheck = false;
                string basePath = "";

                LdapConnection conn = new LdapConnection();
                conn.Connect("***.ir", 389);
                try
                {
                    conn.Bind("***\\" + request.User, request.Pass);
                    basePath = "DC=***,DC=***";
                }
                catch (Exception ex)
                {
                    var code = ex.HResult;
                    if (code == -2146233088)
                    {
                        secondLdapCheck = true;
                    }
                }

                if (secondLdapCheck)
                {
                    conn = new LdapConnection();
                    conn.Connect("***.***", 389);
                    try
                    {
                        basePath = "DC=***,DC=***";
                        conn.Bind("***\\" + request.User, request.Pass);
                    }
                    catch (Exception ex)
                    {
                        var code = ex.HResult;
                        if (code == -2146233088)
                        {
                            Console.WriteLine("Password Error");
                            return new ApiResult<LoginDto>()
                            {
                                StatusCode = EStatusCode.UnAuthorize,
                                Message = "",
                                MessageEn = "Password Error",
                                Data = new LoginDto()
                                {
                                    Tokens = null,
                                    Roles = null,
                                    User = null
                                }
                            };
                        }
                    }
                }
                string[] attrs = new string[] { "memberOf" };
                string searchFilter = "(&(samaccountname=" + request.user + "))";


                LdapSearchConstraints cons = conn.SearchConstraints;
                cons.ReferralFollowing = true;
                conn.Constraints = cons;

                LdapSearchResults lsc = (LdapSearchResults)conn.Search(basePath,
                                             2,
                                             searchFilter,
                                             attrs,
                                             false);

                while (lsc.HasMore())
                {
                    LdapEntry nextEntry = null;
                    try
                    {
                        nextEntry = lsc.Next();
                    }
                    catch (LdapReferralException eR)
                    {
                        Debug.WriteLine(eR.LdapErrorMessage);
                    }
                    catch (LdapException e)
                    {
                        Console.WriteLine("Error: " + e.LdapErrorMessage);
                        continue;
                    }

                    if (nextEntry != null)
                    {
                        if (nextEntry.GetAttributeSet().ContainsKey("memberof"))
                        {
                            var samaccountname = nextEntry.GetAttribute("memberof");
                            var LdapRold = "";

                            foreach (var word in samaccountname.ToString().Split(','))
                            {
                                if (word.Contains("CN"))
                                {
                                    word.Replace(",", "");

                                    Console.WriteLine(word + "\n");
                                    LdapRold += "'" + word.Split("CN=")[1] + "'" + ",";
                                }

                            }
                            LdapRold = LdapRold.Remove(LdapRold.Length - 1);

                            string queryString = "!!!!!";
                            Console.WriteLine(queryString);
                            string connectionString = _config["ConnectionStrings:DefaultConnection"];
                            using (SqlConnection connection = new SqlConnection(connectionString))
                            {
                                SqlCommand command = new SqlCommand(queryString, connection);
                                command.Parameters.AddWithValue("@ServiceId", "ServiceId");
                                connection.Open();
                                SqlDataReader reader = command.ExecuteReader();
                                try
                                {
                                    while (reader.Read())
                                    {
                                        service.Add((String.Format("{0}", reader["ServiceId"])).Trim());
                                    }
                                }
                                finally
                                {
                                    reader.Close();
                                }
                            }

                        }
                    }
                }
                Console.WriteLine(service);
                conn.Disconnect();



                var user = await _unitOfWork.Users.GetUserByLdapUsername("***\\" + request.User);
                var userClaims = await _unitOfWork.UserClaims.GetByUserId_v2(user.Id2.Value);

                if (user == null)
                    return new ApiResult<LoginDto>() { StatusCode = EStatusCode.NotFound };

                var deviceId = Guid.NewGuid();
                Tokens tokens = TokenHelper.GenerateTokens(user, deviceId, service, userClaims, null); ;

                return new ApiResult<LoginDto>()
                {
                    StatusCode = EStatusCode.Success,
                    Message = "",
                    MessageEn = "",
                    Data = new LoginDto()
                    {
                        Tokens = tokens,
                        Roles = null,
                        User = user
                    }
                };
            }
        }
    }
}