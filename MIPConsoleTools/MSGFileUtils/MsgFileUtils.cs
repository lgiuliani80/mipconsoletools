using OpenMcdf;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace LLoydsMonitorFolderForDecrypt.MSGFileUtils
{
    // Refer https://interoperability.blob.core.windows.net/files/MS-OXMSG/%5bMS-OXMSG%5d.pdf

    public static class MsgFileUtils
    {
        internal static byte[] EncodePropertyValue<T>(T value)
        {
            var result = new byte[8];

            switch (value)
            {
                case bool b:
                    result[0] = (byte)(b ? 1 : 0);
                    break;

                case short s:
                    Array.Copy(BitConverter.GetBytes(s), result, 2);
                    break;

                case int i:
                    Array.Copy(BitConverter.GetBytes(i), result, 4);
                    break;

                case float f:
                    Array.Copy(BitConverter.GetBytes(f), result, 4);
                    break;

                case double d:
                    Array.Copy(BitConverter.GetBytes(d), result, 8);
                    break;

                case long l:
                    Array.Copy(BitConverter.GetBytes(l), result, 8);
                    break;

                case DateTime dt:
                    Array.Copy(BitConverter.GetBytes(dt.ToFileTimeUtc()), result, 8);
                    break;
            }

            return result;
        }

        public record PrimitiveProperty(AbstractPrimitiveTypesProperties PropertiesContainer, MsgPropertyIds PropertyId, MsgPropertyTypes PropertyType, MsgPropertyFlags PropertyFlags, int Index)
        {
            public byte[] RawValue => PropertiesContainer.PropertiesStream.Skip(Index + 8).Take(8).ToArray();

            public T GetValue<T>() where T:new()
            {
                var recordSpan = PropertiesContainer.PropertiesStream.AsSpan(Index, 16);
                var record = recordSpan.ToArray();

                switch (new T())
                {
                    case bool _:
                        if (PropertyType == MsgPropertyTypes.PtypBoolean)
                        {
                            var value = BitConverter.ToBoolean(record, 8);
                            return (T)(object)value;
                        }
                        break;

                    case short _:
                        if (PropertyType == MsgPropertyTypes.PtypInteger16)
                        {
                            var value = BitConverter.ToInt16(record, 8);
                            return (T)(object)value;
                        }
                        break;

                    case int _:
                        if (PropertyType == MsgPropertyTypes.PtypInteger32)
                        {
                            var value = BitConverter.ToInt32(record, 8);
                            return (T)(object)value;
                        }
                        break;

                    case float _:
                        if (PropertyType == MsgPropertyTypes.PtypFloating32)
                        {
                            var value = BitConverter.ToSingle(record, 8);
                            return (T)(object)value;
                        }
                        break;

                    case double _:
                        if (PropertyType == MsgPropertyTypes.PtypFloating64)
                        {
                            var value = BitConverter.ToDouble(record, 8);
                            return (T)(object)value;
                        }
                        break;

                    case long _:
                        if (PropertyType == MsgPropertyTypes.PtypInteger64)
                        {
                            var value = BitConverter.ToInt64(record, 8);
                            return (T)(object)value;
                        }
                        break;

                    case DateTime _:
                        if (PropertyType == MsgPropertyTypes.PtypTime)
                        {
                            var value = BitConverter.ToInt64(record, 8);
                            return (T)(object)DateTime.FromFileTime(value);
                        }
                        break;

                    case RawPropertyContent _:
                        return (T)(object)new RawPropertyContent
                        {
                            PropertyFlags = PropertyFlags,
                            PropertyId = PropertyId,
                            PropertyType = PropertyType,
                            PropertyValue = record.Skip(8).Take(8).ToArray()
                        };
                }
                throw new ArgumentException("Unsupported data type");
            }

            public void SetValue<T>(T value)
            {
                EncodePropertyValue(value).CopyTo(PropertiesContainer.PropertiesStream, Index + 8);
            }
        }

        public abstract class AbstractPrimitiveTypesProperties
        {
            public byte[] PropertiesStream { get; private set; }
            public int Offset { get; init; }

            public AbstractPrimitiveTypesProperties(byte[] bytes, int offset)
            {
                PropertiesStream = bytes;
                Offset = offset;
            }

            public IEnumerable<PrimitiveProperty> ReadProperties()
            {
                int index = Offset;
                while (index + 16 <= PropertiesStream.Length)
                {
                    var record = PropertiesStream.AsSpan(index, 16).ToArray();

                    var propType = (MsgPropertyTypes)BitConverter.ToUInt16(record, 0);
                    var propId = (MsgPropertyIds)BitConverter.ToUInt16(record, 2);
                    var propFlags = (MsgPropertyFlags)BitConverter.ToUInt32(record, 4);

                    yield return new PrimitiveProperty(this, propId, propType, propFlags, index);

                    index += 16;
                }
            }

            public PrimitiveProperty AppendProperty(MsgPropertyIds propertyId, MsgPropertyTypes propertyType, MsgPropertyFlags propertyFlags)
            {
                var newPropertiesStream = new byte[PropertiesStream.Length + 16];
                Array.Copy(PropertiesStream, newPropertiesStream, PropertiesStream.Length);

                var record = newPropertiesStream.AsSpan(PropertiesStream.Length, 16);

                BitConverter.GetBytes((ushort)propertyType).CopyTo(record);
                BitConverter.GetBytes((ushort)propertyId).CopyTo(record[2..]);
                BitConverter.GetBytes((uint)propertyFlags).CopyTo(record[4..]);

                PropertiesStream = newPropertiesStream;

                return new PrimitiveProperty(this, propertyId, propertyType, propertyFlags, PropertiesStream.Length - 16);
            }
        }

        public class TopLevelProperties : AbstractPrimitiveTypesProperties
        {
            const int HEADER_SIZE = 32;

            public TopLevelProperties() : base(new byte[HEADER_SIZE], HEADER_SIZE)
            {
            }

            public TopLevelProperties(byte[] bytes) : base(bytes, HEADER_SIZE)
            {
            }

            public uint NextRecipientID 
            {
                get => BitConverter.ToUInt32(PropertiesStream, 8);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 8);
            }

            public uint NextAttachmentID
            {
                get => BitConverter.ToUInt32(PropertiesStream, 8);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 8);
            }

            public uint RecipientCount
            {
                get => BitConverter.ToUInt32(PropertiesStream, 12);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 12);
            }

            public uint AttachmentCount
            {
                get => BitConverter.ToUInt32(PropertiesStream, 12);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 12);
            }
        }

        public class EmbeddedMessageProperties : AbstractPrimitiveTypesProperties
        {
            const int HEADER_SIZE = 24;

            public EmbeddedMessageProperties() : base(new byte[HEADER_SIZE], HEADER_SIZE)
            {
            }

            public EmbeddedMessageProperties(byte[] bytes) : base(bytes, HEADER_SIZE)
            {
            }

            public uint NextRecipientID
            {
                get => BitConverter.ToUInt32(PropertiesStream, 8);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 8);
            }

            public uint NextAttachmentID
            {
                get => BitConverter.ToUInt32(PropertiesStream, 8);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 8);
            }

            public uint RecipientCount
            {
                get => BitConverter.ToUInt32(PropertiesStream, 12);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 12);
            }

            public uint AttachmentCount
            {
                get => BitConverter.ToUInt32(PropertiesStream, 12);
                set => BitConverter.GetBytes(value).CopyTo(PropertiesStream, 12);
            }
        }

        public class AttachmentProperties : AbstractPrimitiveTypesProperties
        {
            const int HEADER_SIZE = 8;

            public AttachmentProperties() : base(new byte[HEADER_SIZE], HEADER_SIZE)
            {
            }

            public AttachmentProperties(byte[] bytes) : base(bytes, HEADER_SIZE)
            {
            }
        }


        public static T GetPrimitiveTypesProperties<T>(this CFStorage cfstorage) where T : AbstractPrimitiveTypesProperties, new()
        {
            if (cfstorage.TryGetStream("__properties_version1.0", out var propDataStream))
            {
                return (T)Activator.CreateInstance(typeof(T), propDataStream.GetData())!;
            }
            return new T();
        }

        public static void SetPrimitiveTypesProperties<T>(this CFStorage cfstorage, T properties) where T : AbstractPrimitiveTypesProperties
        {
            if (!cfstorage.TryGetStream("__properties_version1.0", out var propDataStream))
            {
                propDataStream = cfstorage.AddStream("__properties_version1.0");
            }
            propDataStream.SetData(properties.PropertiesStream);
        }

        public static string GetStreamNameFromPropertyIdType(MsgPropertyIds propertyId, MsgPropertyTypes propertyType)
        {
            return $"__substg1.0_{(ushort)propertyId:X4}{(ushort)propertyType:X4}";
        }

        public static string? GetStringProperty(this CFStorage cfstorage, MsgPropertyIds propertyId)
        {
            var streamName = GetStreamNameFromPropertyIdType(propertyId, MsgPropertyTypes.PtypString);
            if (cfstorage.TryGetStream(streamName, out var stream))
            {
                return Encoding.Unicode.GetString(stream.GetData()).TrimEnd('\0');
            }
            return null;
        }

        public static string GetStringPropertyFailIfNotFound(this CFStorage cfstorage, MsgPropertyIds propertyId)
        {
            var streamName = GetStreamNameFromPropertyIdType(propertyId, MsgPropertyTypes.PtypString);
            return Encoding.Unicode.GetString(cfstorage.GetStream(streamName).GetData()).TrimEnd('\0');
        }

        public static void SetStringProperty(this CFStorage cfstorage, MsgPropertyIds propertyId, string newValue)
        {
            cfstorage.SetRawProperty(propertyId, MsgPropertyTypes.PtypString, Encoding.Unicode.GetBytes(newValue + '\0'));
        }

        public static byte[]? GetRawProperty(this CFStorage cfstorage, MsgPropertyIds propertyId, MsgPropertyTypes propertyType)
        {
            var streamName = GetStreamNameFromPropertyIdType(propertyId, propertyType);
            if (cfstorage.TryGetStream(streamName, out var stream))
            {
                return stream.GetData();
            }
            return null;
        }

        public static void SetRawProperty(this CFStorage cfstorage, MsgPropertyIds propertyId, MsgPropertyTypes propertyType, byte[] content)
        {
            var streamName = GetStreamNameFromPropertyIdType(propertyId, propertyType);
            if (!cfstorage.TryGetStream(streamName, out var propDataStream))
            {
                propDataStream = cfstorage.AddStream("__properties_version1.0");
            }
            propDataStream.SetData(content);
        }
    }

    public class RawPropertyContent
    {
        public MsgPropertyTypes PropertyType { get; set; }
        public MsgPropertyIds PropertyId { get; set; }
        public MsgPropertyFlags PropertyFlags { get; set; }
        public byte[] PropertyValue { get; set; } = new byte[8];  // This will ALWAYS be an 8-byte array
    }
}
