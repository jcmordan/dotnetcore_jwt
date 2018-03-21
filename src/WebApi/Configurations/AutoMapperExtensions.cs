using System.Collections.Generic;
using System.Linq;
using AutoMapper;
using Microsoft.AspNetCore.Builder;
using WebApi.Models;

namespace WebApi.Configurations
{
    public static class AutoMapperExtensions
    {
        public static void UseAutoMapperConfig (this IApplicationBuilder app)
        {
            Mapper.Initialize (config =>
            {
                config.CreateMap<AccessRequest, User> ();
            });
        }

        public static TOut Map<TIn, TOut> (this TIn currentModel)
            where TOut : class
        {
            return Mapper.Map<TIn, TOut> (currentModel);
        }
    }
}