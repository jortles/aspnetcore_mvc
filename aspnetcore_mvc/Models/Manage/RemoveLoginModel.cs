using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace aspnetcore_mvc.Models.Manage
{
    public class RemoveLoginModel
    {
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; }
    }
}
