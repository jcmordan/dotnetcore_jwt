using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace WebApi.Controllers
{
    public class BaseController : Controller
    {
        protected IActionResult BadRequestModelState()
        {
            return BadRequest(ModelState.Values.SelectMany(v => v.Errors.Select(e => e.ErrorMessage)));
        }
    }

}
