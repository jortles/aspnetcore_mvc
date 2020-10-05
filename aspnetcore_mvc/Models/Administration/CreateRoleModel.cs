using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace aspnetcore_mvc.Models.Administration
{
    public class CreateRoleModel
    {
        [Required]
        public string RoleName { get; set; }
    }
}
