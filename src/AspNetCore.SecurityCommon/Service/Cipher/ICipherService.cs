namespace AspNetCore.SecurityCommon
{
    public interface ICipherService
    {
        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="originStr">原始数据</param>
        /// <returns></returns>
        string Encrypt(string originStr);

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptStr">加密数据</param>
        /// <returns></returns>
        string Decrypt(string encryptStr);
    }
}
