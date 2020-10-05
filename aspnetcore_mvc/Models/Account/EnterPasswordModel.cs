using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace aspnetcore_mvc.Models.Account
{
    public class EnterPasswordModel
    {
        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        public string Username { get; set; }
    }
}
