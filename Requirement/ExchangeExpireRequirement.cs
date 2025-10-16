using Microsoft.AspNetCore.Authorization;

namespace AspNetCoreIdentityApp.Requirement
{
    public class ExchangeExpireRequirement : IAuthorizationRequirement
    {


    }
    public class ExchangeExpireRequirementHandler : AuthorizationHandler<ExchangeExpireRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ExchangeExpireRequirement requirement)
        {
            if (!context.User.HasClaim(c => c.Type == "ExchangeExpireDate"))
            {
                context.Fail();
                return Task.CompletedTask;
            }

            var exchangeExpireDate = context.User.FindFirst(c => c.Type == "ExchangeExpireDate");

            if (DateTime.Now > Convert.ToDateTime(exchangeExpireDate.Value))
            {
                context.Fail();
                return Task.CompletedTask;
            }
            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
