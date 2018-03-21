using System;
using System.Collections.Generic;

namespace WebApi.Models
{
    public class UserProfile
    {
        public string UserName { get; set; }
        public string InstanceName {get;set;}
        public string Token { get; set; }
        public DateTime TokenExpirationDate { get; set; }
        public ICollection<string> Access { get; set; }
    }
}
