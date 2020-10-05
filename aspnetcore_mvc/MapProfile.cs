using aspnetcore_mvc.Models;
using aspnetcore_mvc.Models.Account;
using AutoMapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace aspnetcore_mvc
{
    public class MapProfile : Profile
    {
        public MapProfile()
        {
            CreateMap<RegisterModel, ApplicationUser>()
                .ForMember(u => u.UserName, opt => opt.MapFrom(x => x.Email));
        }
    }
}
