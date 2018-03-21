namespace WebApi.Configurations
{
    public class CustomIdentityOptions
    {
        public bool UserRequireUniqueEmail { get; set; }
        public int PasswordRequiredLength { get; set; }
        public bool PasswordRequireDigit { get; set; }
        public bool PasswordRequireNonAlphanumeric { get; set; }
        public bool PasswordRequireUppercase { get; set; }
        public bool PasswordRequireLowercase { get; set; }
        public int LockoutMaxFailedAccessAttempts { get; set; }
    }
}
