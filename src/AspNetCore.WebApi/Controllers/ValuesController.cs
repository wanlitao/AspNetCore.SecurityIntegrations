using FCP.Core;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AspNetCore.WebApi.Controllers
{
    [Route("api/v{api-version:apiVersion}/[controller]")]
    [ApiController]
    [ApiVersion("1.0")]
    public class ValuesController : ControllerBase
    {
        [HttpGet("{prefix}")]
        public Task<FCPDoResult<IList<ValueDetail>>> Get(string prefix)
        {
            IList<ValueDetail> valueStrs = Enumerable.Range(1, 9).Select(m => new ValueDetail { Name = $"{prefix}-{m}", Value = m }).ToList();

            return Task.FromResult(FCPDoResultHelper.doSuccess(valueStrs));
        }

        [HttpPost]
        public Task<FCPDoResult<string>> Add(ValueDetail model)
        {
            if (string.IsNullOrWhiteSpace(model.Name))
                return Task.FromResult(FCPDoResultHelper.doFail<string>("name is null or empty"));

            if (model.Value < 0)
                return Task.FromResult(FCPDoResultHelper.doFail<string>("invalid value"));

            var id = Guid.NewGuid().ToString("N");
            return Task.FromResult(FCPDoResultHelper.doSuccess(id));
        }
    }

    public class ValueDetail
    {
        public string Name { get; set; }

        public int Value { get; set; }
    }
}