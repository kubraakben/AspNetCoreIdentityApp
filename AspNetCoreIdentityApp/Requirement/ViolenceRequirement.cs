using Microsoft.AspNetCore.Authorization;

namespace AspNetCoreIdentityApp.Requirement
{
    public class ViolenceRequirement : IAuthorizationRequirement
    {
        public int ThresholdAge { get; set; }


    }
    public class ViolenceRequirementHandler : AuthorizationHandler<ViolenceRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ViolenceRequirement requirement)
        {
            if (!context.User.HasClaim(c => c.Type == "BirthDate"))
            {
                context.Fail();
                return Task.CompletedTask;
            }
            var birthDateClaim = context.User.FindFirst(c => c.Type == "BirthDate");

            var today = DateTime.Today;
            var birthDate = Convert.ToDateTime(birthDateClaim!.Value);
            var age = today.Year - birthDate.Year;

            if (birthDate > today.AddDays(-age)) age--;

            if (requirement.ThresholdAge > age)
            {
                context.Fail();
                return Task.CompletedTask;

            }
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
