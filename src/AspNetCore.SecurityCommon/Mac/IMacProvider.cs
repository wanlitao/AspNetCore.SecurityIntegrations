namespace AspNetCore.SecurityCommon
{
    public interface IMacProvider
    {
        string AlgorithmName { get; }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="originStr">原始数据</param>
        /// <returns></returns>
        byte[] Encrypt(string originStr);
    }
}
