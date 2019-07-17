namespace AspNetCore.SecurityCommon
{
    public interface ICipherProvider
    {
        string AlgorithmName { get; }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="originStr">原始数据</param>
        /// <returns></returns>
        byte[] Encrypt(string originStr);

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="encryptBytes">加密数据</param>
        /// <returns></returns>
        string Decrypt(byte[] encryptBytes);
    }
}
