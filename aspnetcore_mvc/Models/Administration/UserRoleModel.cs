using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace aspnetcore_mvc.Models.Administration
{
    public class UserRoleModel
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public bool IsSelected { get; set; }
    }
}
