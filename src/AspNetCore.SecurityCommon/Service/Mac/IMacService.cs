namespace AspNetCore.SecurityCommon
{
    public interface IMacService
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="originStr">原始数据</param>
        /// <returns></returns>
        string Encrypt(string originStr);
    }
}
