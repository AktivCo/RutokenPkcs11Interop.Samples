using System;
using System.IO;

using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Asn1.Cms;
using OpenSslPemWriter = Org.BouncyCastle.OpenSsl.PemWriter;
using Org.BouncyCastle.Asn1;

namespace TimeStampTest
{
    class Util
    {
        public static void PrintString(string label, string data)
        {
            Console.WriteLine(label);
            Console.WriteLine(data);
        }


        public static CmsSignedData ReadCmsFromFile(string filename)
        {
            PemReader reader = new PemReader(File.OpenText(filename));
            PemObject pemObject = reader.ReadPemObject();
            reader.Reader.Close();
            return new CmsSignedData(pemObject.Content);
        }

        public static string CmsToPem(CmsSignedData cms)
        {
            StringWriter stringWriter = new StringWriter();
            OpenSslPemWriter pemWriter = new OpenSslPemWriter(stringWriter);
            pemWriter.WriteObject(cms.ContentInfo);
            return stringWriter.ToString();
        }
    }
}
