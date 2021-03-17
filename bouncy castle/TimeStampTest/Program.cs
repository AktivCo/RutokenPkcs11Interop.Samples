
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.Cmp;
using Asn1CmsAttributeTable = Org.BouncyCastle.Asn1.Cms.AttributeTable;
using Asn1CmsAttribute = Org.BouncyCastle.Asn1.Cms.Attribute;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.X509.Store;
using Org.BouncyCastle.X509;

using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;


namespace TimeStampTest
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                CmsSignedData cms = Util.ReadCmsFromFile("cms.pem");
                Util.PrintString("Original CMS signature in PEM is:", Util.CmsToPem(cms));

                TimeStampRequest timeStampRequest = MakeTimeStampRequest(cms);
                Console.WriteLine("TimeStamp request created successfully.");

                Console.WriteLine("Please insert TSA server URL (in form http:// or https://):");
                //string tsaUrl = Console.ReadLine();
                string tsaUrl = "http://www.cryptopro.ru/tsp/tsp.srf";
                TimeStampResponse timeStampResponse = GetTimeStampResponseFromServer(tsaUrl, timeStampRequest);
                Console.WriteLine("TimeStamp response received successfully.");

                timeStampResponse.Validate(timeStampRequest);
                if (timeStampResponse.Status != (int) PkiStatus.Granted
                        && timeStampResponse.Status != (int)PkiStatus.GrantedWithMods)
                    throw new Exception("TimeStamp response status check failed: "
                            + timeStampResponse.Status);
                Console.WriteLine("TimeStamp response validated successfully.");

                Util.PrintString("TimeStamp token in PEM is:",
                        Util.CmsToPem(timeStampResponse.TimeStampToken.ToCmsSignedData()));

                VerifyTimeStampResponseSignature(timeStampResponse);
                Console.WriteLine("TimeStamp token signature verified successfully.");

                cms = AddTimeStampTokenToCms(timeStampResponse, cms);
                Util.PrintString("CMS signature with TimeStamp token in PEM is:", Util.CmsToPem(cms));

                Console.WriteLine("Sample has been completed successfully.");
            }
            catch (Exception e)
            {
                Console.WriteLine("Sample has failed:");
                Console.Write(e.StackTrace);
            }
        }

        private static TimeStampRequest MakeTimeStampRequest(CmsSignedData cms)
        {
            ICollection signerInfos = cms.GetSignerInfos().GetSigners();
            if (signerInfos.Count == 0)
                throw new Exception("No signers found.");
            if (signerInfos.Count != 1)
                throw new Exception("More than 1 signer found.");

            IEnumerator en = signerInfos.GetEnumerator();
            en.MoveNext();
            SignerInformation signerInformation = (SignerInformation)en.Current;

            Gost3411_2012_256Digest gostHash = new Gost3411_2012_256Digest();
            gostHash.BlockUpdate(signerInformation.GetSignature(), 0 , signerInformation.GetSignature().Length);

            byte[] hashFromSignature = new byte[gostHash.GetDigestSize()];
            gostHash.DoFinal(hashFromSignature, 0);

            return new TimeStampRequestGenerator()
                .Generate(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256, hashFromSignature);
        }

        private static TimeStampResponse GetTimeStampResponseFromServer(string serverUrl, TimeStampRequest timeStampRequest)
        {
            HttpWebRequest connection = (HttpWebRequest) WebRequest.Create(serverUrl);
            HttpWebResponse serverResponse = null;

            try {
                byte[] request = timeStampRequest.GetEncoded();
                connection.Method ="POST";
                connection.ContentType = "application/timestamp-query";
                connection.ContentLength = request.Length;

                using (var stream = connection.GetRequestStream())
                {
                    stream.Write(request, 0, request.Length);
                }

                serverResponse = (HttpWebResponse)connection.GetResponse();
                if (serverResponse.StatusCode != HttpStatusCode.OK)
                    throw new IOException("Received HTTP error: " + serverResponse.StatusCode);

                Stream inStream = serverResponse.GetResponseStream();
                TimeStampResp response = TimeStampResp.GetInstance(new Asn1InputStream(inStream).ReadObject());
                    return new TimeStampResponse(response);
            } finally
            {
                if (serverResponse != null)
                    serverResponse.Close();
            }
        }

        private static List<byte[]> GetTrustedCerts()
        {
            var trustedCerts = new List<byte[]>();
            foreach (string filePath in Directory.GetFiles("trusted"))
            {
                byte[] content = File.ReadAllBytes(filePath);
                trustedCerts.Add(content);
            }

            return trustedCerts;
        }

        private static List<byte[]> GetCerts()
        {
            var certs = new List<byte[]>();
            foreach (string filePath in Directory.GetFiles("certs"))
            {
                byte[] content = File.ReadAllBytes(filePath);
                certs.Add(content);
            }

            return certs;
        }


        private static void VerifyTimeStampResponseSignature(TimeStampResponse timeStampResponse)
        {
            Pkcs7VerificationResult verificationResult = null;
            CmsSignedData responseCms = timeStampResponse.TimeStampToken.ToCmsSignedData();

            byte[] cmsData = responseCms.GetEncoded("DER");

            var x509Store = new CkVendorX509Store(GetTrustedCerts(), GetCerts());

            var factories = new RutokenPkcs11InteropFactories();
            using (var pkcs11 = factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(factories, "rtpkcs11ecp.dll", Net.Pkcs11Interop.Common.AppType.MultiThreaded))
            {
                IRutokenSlot slot = pkcs11.GetRutokenSlotList(Net.Pkcs11Interop.Common.SlotsType.WithTokenPresent)[0];
                using (var session = slot.OpenRutokenSession(Net.Pkcs11Interop.Common.SessionType.ReadOnly))
                {
                    verificationResult = session.PKCS7Verify(cmsData, x509Store, Net.RutokenPkcs11Interop.Common.VendorCrlMode.OptionalClrCheck, 0);
                }
            }
            if (verificationResult != null && !verificationResult.IsValid)
                throw new Exception("Attached CMS signature is invalid");
        }

        private static CmsSignedData AddTimeStampTokenToCms(TimeStampResponse timeStampResponse, CmsSignedData cms)
        {
            Asn1InputStream asn1InputStream = new Asn1InputStream(timeStampResponse.TimeStampToken.GetEncoded());
            DerSet ds = new DerSet(asn1InputStream.ReadObject());

            Asn1CmsAttribute timestampTokenAttr = new Asn1CmsAttribute(PkcsObjectIdentifiers.IdAASignatureTimeStampToken, ds);
            Asn1EncodableVector derVector = new Asn1EncodableVector();
            derVector.Add(timestampTokenAttr);
            Asn1CmsAttributeTable attributeTable = new Asn1CmsAttributeTable(derVector);

            ICollection signerInfos = cms.GetSignerInfos().GetSigners();
            IEnumerator en = signerInfos.GetEnumerator();
            en.MoveNext();

            SignerInformation signerInformation = SignerInformation.ReplaceUnsignedAttributes((SignerInformation) en.Current, attributeTable);
            var replacingSignerInfos = new List<SignerInformation>();
            replacingSignerInfos.Add(signerInformation);
            SignerInformationStore signerInformationStore = new SignerInformationStore(replacingSignerInfos);

            return CmsSignedData.ReplaceSigners(cms, signerInformationStore);
        }

    }
}
