using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace WebApi.Configurations
{
    public static class JsonOptions
    {
        public static void Configure(MvcJsonOptions options)
        {
            options.SerializerSettings.Converters.Add(new StringEnumConverter());
            options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
        }
    }
}
