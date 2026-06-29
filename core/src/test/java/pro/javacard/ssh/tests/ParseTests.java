// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.ssh.tests;

import org.testng.Assert;
import org.testng.SkipException;
import org.testng.annotations.Test;
import pro.javacard.ssh.SSHCertificate;
import pro.javacard.ssh.SSHIdentity;
import pro.javacard.ssh.SSHPublicKey;
import pro.javacard.ssh.agent.messages.*;
import pro.javacard.ssh.dtbs.UserAuthPayload;
import pro.javacard.ssh.utils.Helpers;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Optional;

public class ParseTests {

    @Test
    public void testParseExtensionBind() {
        var msg1 = Helpers.fromHex("000000f01b0000001873657373696f6e2d62696e64406f70656e7373682e636f6d000000330000000b7373682d65643235353139000000206d49bea97bb45ab3fd3a3bb2a257c914ebdf44c8684d20940a850cd841977925000000400ef27ff4fe145d253c005f152c54c88c85063161a545d0175b9053ed605742160ba1cbf7a0bf7bfccd0c4276e467cb135edbdadaaa7ae3ccc836fc8877bfc9ac000000530000000b7373682d65643235353139000000407025c32c183c0ee2b62e87917103de1966f153f90aa01c0cb6f57f88e5e1e4cf7e1ce533655bc7e2b8c4cb5e45f64830a093128c082fd5b744d3a4875f660c0d00");
        var buffer = ByteBuffer.wrap(msg1);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENTC_EXTENSION);
        var ext = Extension.fromByteBuffer(buffer);
        Assert.assertEquals(ext.getType(), SessionBindExtension.SESSION_BIND);
        Assert.assertFalse(buffer.hasRemaining());
    }

    @Test
    public void testParseIdentitiesAnswer2() {
        var msg2 = Helpers.fromHex("000002310c00000004000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104eb0ffe34132aa399d191f21f4214dcd28bdccb137d88f5e92317e16b8295e26efba790570ee4f174863531caf358ddb71900b24f233a49c734177d687bb6d2270000001365636473612d736861322d6e69737470323536000000680000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041046ce054c4f72c344813fe1b5d50ff2eeffe65d44ad9dce33b77a85d3d533591bc4edcd639db279bca076059c02cfedfcc645632356eb2307fe24d53d3af40f2c90000001365636473612d736861322d6e69737470323536000000680000001365636473612d736861322d6e69737470323536000000086e6973747032353600000041045e01251250cbc791cfa28ec6447d2aa987d417e1c821bf6471673d55492c79b050c1bbc98e61839934c0d5f5f25926fd4e1e29ea489849b6510d57c7bda14eec0000001365636473612d736861322d6e69737470323536000000880000001365636473612d736861322d6e69737470333834000000086e6973747033383400000061048b3398ee9f2e10b3d6e1ec616065f848be44a3d65010ab7bb143f83b97d47d038e538eb76cad605d7dcbd9c0d681a43caac510aa2e984c462fc92029366d30483555367f7da2318466301011ac066c5378ca529d8c2eb8d6abc2af6d7acf49270000001365636473612d736861322d6e69737470333834");
        var buffer = ByteBuffer.wrap(msg2);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
        var answer = IdentitiesAnswer.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(answer.getIdentities().size(), 4);
    }

    @Test
    public void testParseSignRequest() {
        var msg3 = Helpers.fromHex("000001b80d000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104eb0ffe34132aa399d191f21f4214dcd28bdccb137d88f5e92317e16b8295e26efba790570ee4f174863531caf358ddb71900b24f233a49c734177d687bb6d22700000143000000400ef27ff4fe145d253c005f152c54c88c85063161a545d0175b9053ed605742160ba1cbf7a0bf7bfccd0c4276e467cb135edbdadaaa7ae3ccc836fc8877bfc9ac32000000066d617274696e0000000e7373682d636f6e6e656374696f6e000000237075626c69636b65792d686f7374626f756e642d763030406f70656e7373682e636f6d010000001365636473612d736861322d6e69737470323536000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104eb0ffe34132aa399d191f21f4214dcd28bdccb137d88f5e92317e16b8295e26efba790570ee4f174863531caf358ddb71900b24f233a49c734177d687bb6d227000000330000000b7373682d65643235353139000000206d49bea97bb45ab3fd3a3bb2a257c914ebdf44c8684d20940a850cd84197792500000000");

        var buffer = ByteBuffer.wrap(msg3);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENTC_SIGN_REQUEST);
        var request = SignRequest.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertTrue(request.getParsed() instanceof UserAuthPayload);
        Assert.assertEquals(((UserAuthPayload) request.getParsed()).method(), "publickey-hostbound-v00@openssh.com");
    }

    @Test
    public void testParseSignResponse() {
        var msg4 = Helpers.fromHex("000000680e000000630000001365636473612d736861322d6e69737470323536000000480000002009d03eba1b8ca93e8f472c8ce102efb585b0df2cad197e7ff09f8c8646cc2f6e000000205cbf564814d2693cebf0c45555fd6e3ca4166f3526458f1fe339fe5017f3e8a1");

        var buffer = ByteBuffer.wrap(msg4);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENT_SIGN_RESPONSE);
        var resp = SignResponse.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
    }

    @Test
    public void testParseIdentitiesAnswer() {
        var msg6 = Helpers.fromHex("000000540c00000001000000330000000b7373682d6564323535313900000020ea0ef9125ad9ca3baf30ae2862544447dd90ed9a57625d1c060719d9aa5fe35d000000146d617274696e40736973616c696b2e6c6f63616c");

        var buffer = ByteBuffer.wrap(msg6);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
        var resp = IdentitiesAnswer.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(resp.getIdentities().size(), 1);
        var identity = resp.getIdentities().iterator().next();
        Assert.assertEquals(identity.getKey().getFingerprint(), "SHA256:TC6B+bBVCFL6Fa4TBib4R8VNnFrAyersUbMWFuK6mwU");
        Assert.assertEquals(identity.getComment(), Optional.of("martin@sisalik.local"));
        Assert.assertEquals(identity.getSSHType(), "ssh-ed25519");
    }

    @Test
    public void testRemoveIdentity() {
        var msg8 = Helpers.fromHex("0000006d12000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104755f240611b8f61127bdb63a0afe2f18e946e57643db67c32de67849d5dbdcad2c3e15ae2155683c26024aa8e8b756db28552037499587944e682e3ca03275b0");
        var buffer = ByteBuffer.wrap(msg8);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENTC_REMOVE_IDENTITY);
        var removeIdentity = RemoveIdentity.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(removeIdentity.getIdentity().getKey().getFingerprint(), "SHA256:B3f52+KchvplNwnua3FjmqI3q6uykHp7SxXBgu1d7Q8");
    }

    @Test
    public void testRemoveCert() {
        var msg8 = Helpers.fromHex("0000042e12000004290000002865636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d00000020bfd10fa10afbd665a47adf365fd71b35ed4f692038ee0242b56b2f4f10f3c1f6000000086e6973747032353600000041047ad232277aad53f165acf52054ed2a153826932a8395a9eb44ce3a3b0fefbfe79d2b0cea2570bbc6c828ba9a3ac83a26e18ba646e8a6893169a2a20c783df8540000000000000000000000020000000a6b6173742e6c6f63616c0000001b0000000a6b6173742e6c6f63616c000000096c6f63616c686f737400000000677a8ca000000000695a6f0d00000000000000000000000000000197000000077373682d727361000000030100010000018100b00889fcdca02fbaebab56804d9d34a790059ddbf59653be49f9caceff6267c0bd80e4e8de08691c9f06ec1078bcfe7b7064ef546e9176f1b6b30778d1715e4f75cac90acb0ba9a83a60a939be65e77af4f911dcf2f777d94ce932e059773d2c15bae6702020072619fa66c8d1a505aa0a0896f6ff05f8734d1b161c429d4cb5df5507e6594f6e323d85aeabd641b1137a2d642a565a27fb95c85693fcf439194edeac9a85be226af530f239fde09b33df3ba7781e6f0a5a8823742e658e7cf4610bafcac7fe1b186723d9d36711a8f704ee172183b476f9fe5a3c98c180aa325f39e1f3e338f23458d0dcdc43028cb9c077dc718175943bc43ce421a85f1f58a09cc17fcd25e5f514470b38d85ecb104e1e6f76186fa5b5e132a026bcae876dd111be51ca6a4d144c0af78254353cbdebb752a8c25f54f180c361a37a64c26eae09a3b9e02fe74d241bf3ffa2a07da3cb56c45b1d47dc419e9b8173b82ae331a1dad72c76eb2d16496de2ca1b33b99b382cbee73a846599b0227f2749a392e1000001940000000c7273612d736861322d353132000001802a4402315b5ce69462d63a4a360c51b0c9a15f79dd6a740244fc8c173416cf6cfc304f16b432e72d30c115ef34a9ac5cf789769472dedd82e5c802cb011802b1328754824832e8efc1bfbadcd0fe36d209a567ff7bb9d2e4c0219a4d4f626ce4cbd76436bad76ed2090fb32757ed1b725ddf864922765cb487e48030a796fcdcdff6e6fbe095187dc84d5a0df984cea49ec92f453915a6210520c4a69dcfa36f386adc3e73772ddf0346eaebcdb96a18f338a61e0df1ebdb4d0d5d3f9a08094e93a7c66c230d739374fe01c3d67bafae5ea6e2e755ec5385d45730ae2a2108621719c4af8526d556e6238f1858369e0a5fade4aad21a4f586455a05ee988666ca5232a85aed34d1bb38fcd8f1972df0a9d5643ad4062c78ec86d01a69c74c55167400d100e29f8cf8d80c4138b84f125e4b2a0e3d19a037bab3e66ae4f3909dcb4cb8d8d2162f9e73a94371f90cc8cd61f64f2aa5aeed327677ddb15bc969d0a4bc5a478d64e7e424487456819f298df088a1933663394793017fe7001d145d1");
        var buffer = ByteBuffer.wrap(msg8);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENTC_REMOVE_IDENTITY);
        var removeIdentity = RemoveIdentity.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(removeIdentity.getIdentity().getKey().getFingerprint(), "SHA256:5DmYCoIkCgEoOnbx3K+UXLhHVh8pX8GXgf7IS8i9QPo");
    }

    @Test
    public void testParseCertIdentitiesAnswer() {
        var msg10 = Helpers.fromHex("000003440c00000003000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104755f240611b8f61127bdb63a0afe2f18e946e57643db67c32de67849d5dbdcad2c3e15ae2155683c26024aa8e8b756db28552037499587944e682e3ca03275b0000000146d617274696e40736973616c696b2e6c6f63616c000002500000002865636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d00000020018e38273e48c6fcc9d171367644d841cea7f8c17f60b9f2890393398de2928a000000086e697374703235360000004104755f240611b8f61127bdb63a0afe2f18e946e57643db67c32de67849d5dbdcad2c3e15ae2155683c26024aa8e8b756db28552037499587944e682e3ca03275b0000000000000000000000001000000176d617274696e406d617274696e70616c6a616b2e6e65740000001200000004726f6f74000000066d617274696e000000006772375800000000689987b40000000000000082000000157065726d69742d5831312d666f7277617264696e6700000000000000177065726d69742d6167656e742d666f7277617264696e6700000000000000167065726d69742d706f72742d666f7277617264696e67000000000000000a7065726d69742d707479000000000000000e7065726d69742d757365722d72630000000000000000000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104d82e48ad1008ad5d800fe1714a45e79cdad177a3554e164650b1bcc5a1ecf91449bca3c957951d55d524ec8c06fe882e225b3bc53c5f6ab39d3f9dd2e867c813000000640000001365636473612d736861322d6e697374703235360000004900000020450c23822b77c05b5219e7b7988ebe1bb1cedea384e8c165f664a3c9ab9b46d90000002100dbeb17de4fd28812a05d3f81a95093c0f4a7bae3bf1a2751177b53312d97c7d0000000146d617274696e40736973616c696b2e6c6f63616c000000330000000b7373682d6564323535313900000020ea0ef9125ad9ca3baf30ae2862544447dd90ed9a57625d1c060719d9aa5fe35d000000146d617274696e40736973616c696b2e6c6f63616c");

        var buffer = ByteBuffer.wrap(msg10);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
        var identitiesAnswer = IdentitiesAnswer.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(identitiesAnswer.getIdentities().size(), 3);
    }

    @Test
    public void testParseExtensions() {
        var msg11 = Helpers.fromHex("000002511b0000001873657373696f6e2d62696e64406f70656e7373682e636f6d00000194000000207373682d656432353531392d636572742d763031406f70656e7373682e636f6d00000020c21d84465c20b0477db4da10103420fb98f92d83616f0def0656de9750423eb300000020ba6f85dd4fee09a44c521043b9bb8bcd824550107e9c5acc2b43eac5f1825d210000000000000000000000020000000a6b6173742e6c6f63616c0000001b0000000a6b6173742e6c6f63616c000000096c6f63616c686f7374000000006772314000000000695213a6000000000000000000000000000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afe7f730e582c29f3c9040f207e8cdec604a65e9dc5a69588c57467423f534994dbd1f150e153298f6758d5558aa35c3d95595204da47f055517d5d691dac9e2000000630000001365636473612d736861322d6e6973747032353600000048000000200e7a8326ca1b8624b8fd3c79a6829f01836487923bfccc55055a5ccf73e4e5a6000000206ce1a94e7920a5952e6e8ec9785f6cf0bde73f4c378d7ad5ef5d5c339929ef1c000000404c642b90df4353b94aa14c9a5e1f90619b9c9405199fd6882fe69e1192d4c2abf5eddc714a9c53d2ebc31a1da1ee03ad55e27f4d66b2ee8f3ca6d12e7a96f5aa000000530000000b7373682d656432353531390000004054b268b64bb87545624bd665c748926c77c5fe51513be572a0df9e590a7914d8748185edc565f402f111eb213b34d28660ed10d66b88eceb146d3c69c5236a0200");

        var buffer = ByteBuffer.wrap(msg11);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENTC_EXTENSION);
        var ext = Extension.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
    }

    @Test
    public void testEdFingerprint() {
        var kb = "AAAAC3NzaC1lZDI1NTE5AAAAIOoO+RJa2co7rzCuKGJUREfdkO2aV2JdHAYHGdmqX+Nd";
        var key = Base64.getDecoder().decode(kb);
        var buffer = ByteBuffer.wrap(key);
        var pk = SSHPublicKey.PARSER.fromByteBuffer(buffer);
        Assert.assertEquals(pk.getFingerprint(), "SHA256:TC6B+bBVCFL6Fa4TBib4R8VNnFrAyersUbMWFuK6mwU");
        System.out.println(pk);

        var pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMwy55JpcwPEpe9QmRBVe0PLPWzBXgBejcrKJqUu5Py/ host ca ed25519";

        var identity = SSHIdentity.fromString(pub);
        Assert.assertEquals(identity.getKey().getFingerprint(), "SHA256:cChPkCiOEeaxzyLoVOfSidTR0AQDL4hC35Qg2HnVPTU");
        Assert.assertEquals(identity.getComment(), Optional.of("host ca ed25519"));
    }

    @Test
    public void testEcFingerprint() {
        var kb = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHVfJAYRuPYRJ722Ogr+LxjpRuV2Q9tnwy3meEnV29ytLD4VriFVaDwmAkqo6LdW2yhVIDdJlYeUTmguPKAydbA=";
        var key = Base64.getDecoder().decode(kb);
        var buffer = ByteBuffer.wrap(key);
        var pk = SSHPublicKey.PARSER.fromByteBuffer(buffer);
        Assert.assertEquals(pk.getFingerprint(), "SHA256:B3f52+KchvplNwnua3FjmqI3q6uykHp7SxXBgu1d7Q8");
        System.out.println(pk);
    }

    @Test
    public void testParseCert() {
        var cert = "AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgAY44Jz5IxvzJ0XE2dkTYQc6n+MF/YLnyiQOTOY3ikooAAAAIbmlzdHAyNTYAAABBBHVfJAYRuPYRJ722Ogr+LxjpRuV2Q9tnwy3meEnV29ytLD4VriFVaDwmAkqo6LdW2yhVIDdJlYeUTmguPKAydbAAAAAAAAAAAAAAAAEAAAAXbWFydGluQG1hcnRpbnBhbGphay5uZXQAAAASAAAABHJvb3QAAAAGbWFydGluAAAAAGdyN1gAAAAAaJmHtAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNguSK0QCK1dgA/hcUpF55za0XejVU4WRlCxvMWh7PkUSbyjyVeVHVXVJOyMBv6ILiJbO8U8X2qznT+d0uhnyBMAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIEUMI4Ird8BbUhnnt5iOvhuxzt6jhOjBZfZko8mrm0bZAAAAIQDb6xfeT9KIEqBdP4GpUJPA9Ke6478aJ1EXe1MxLZfH0A==";
        var crt = Base64.getDecoder().decode(cert);
        var buffer = ByteBuffer.wrap(crt);
        var sshCertificate = SSHCertificate.PARSER.fromByteBuffer(buffer);
        System.out.println(sshCertificate);
        Assert.assertNotNull(sshCertificate);
        Assert.assertEquals(sshCertificate.getSSHType(), "ecdsa-sha2-nistp256-cert-v01@openssh.com");
        var payload = sshCertificate.getPayload();
        Assert.assertEquals(payload.serial(), BigInteger.ZERO);
        Assert.assertEquals(payload.id(), "martin@martinpaljak.net");
        Assert.assertEquals(payload.principals().size(), 2);
        Assert.assertEquals(payload.principals().getFirst(), "root");
        Assert.assertEquals(payload.principals().getLast(), "martin");
        Assert.assertEquals(payload.options().size(), 0);
        Assert.assertEquals(payload.extensions().size(), 5);
    }


    @Test
    public void testParseCertIdentitiesAnswerEdSk() {
        var msg = Helpers.fromHex("000003a20c00000004000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104755f240611b8f61127bdb63a0afe2f18e946e57643db67c32de67849d5dbdcad2c3e15ae2155683c26024aa8e8b756db28552037499587944e682e3ca03275b0000000146d617274696e40736973616c696b2e6c6f63616c000002500000002865636473612d736861322d6e697374703235362d636572742d763031406f70656e7373682e636f6d00000020018e38273e48c6fcc9d171367644d841cea7f8c17f60b9f2890393398de2928a000000086e697374703235360000004104755f240611b8f61127bdb63a0afe2f18e946e57643db67c32de67849d5dbdcad2c3e15ae2155683c26024aa8e8b756db28552037499587944e682e3ca03275b0000000000000000000000001000000176d617274696e406d617274696e70616c6a616b2e6e65740000001200000004726f6f74000000066d617274696e000000006772375800000000689987b40000000000000082000000157065726d69742d5831312d666f7277617264696e6700000000000000177065726d69742d6167656e742d666f7277617264696e6700000000000000167065726d69742d706f72742d666f7277617264696e67000000000000000a7065726d69742d707479000000000000000e7065726d69742d757365722d72630000000000000000000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104d82e48ad1008ad5d800fe1714a45e79cdad177a3554e164650b1bcc5a1ecf91449bca3c957951d55d524ec8c06fe882e225b3bc53c5f6ab39d3f9dd2e867c813000000640000001365636473612d736861322d6e697374703235360000004900000020450c23822b77c05b5219e7b7988ebe1bb1cedea384e8c165f664a3c9ab9b46d90000002100dbeb17de4fd28812a05d3f81a95093c0f4a7bae3bf1a2751177b53312d97c7d0000000146d617274696e40736973616c696b2e6c6f63616c000000330000000b7373682d6564323535313900000020ea0ef9125ad9ca3baf30ae2862544447dd90ed9a57625d1c060719d9aa5fe35d000000146d617274696e40736973616c696b2e6c6f63616c0000004a0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000020b4f7044e5e947fc3c08f44ef9e5490e8452a03ed6eee1600665e99c773a3005e000000047373683a0000000c596f757220436f6d6d656e74");
        var buffer = ByteBuffer.wrap(msg);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
        var identitiesAnswer = IdentitiesAnswer.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(identitiesAnswer.getIdentities().size(), 4);
    }

    @Test
    public void testParseRSAKey() {
        var msg = Helpers.fromHex("000002320c0000000100000217000000077373682d727361000000030100010000020100bdd3ca3aeed83e24b9b4c6c67c5bfc33e618d5b96944233f40cca7dcf7a14ac355b6f8e50961acceecb2b517145a5541d95bef9938ef6898806c795d45d2ca8b2fa0c66e957704b59edaa33f8c4f51d0e1574110d15896687bcb3dc4abc9affb27433b2c1dcde0c43999e6b1bd55529af218286eb0964cb93d84313b1dd33cbe7e889a6160f3edef016e856cad28f0051f07d43bd7a213a42371a4e03037ea76ac17b8afc8a0e0b09b16b31730c07f36124ea102c6cfd5d0d71edd639795e607605c6c1ae32d5a06f1b6dade70c66ce6e630afdded258e908a349f33234e0046709a74ef43f8b4030ac2a9e1e42b48ea53f116bbc0ac6f9776725da5c25c01c0474205a8aa60567a135e7b28d2a0fda561fc48a0134cdd34b648d027b1206b281a1b9cf6838e871a502920a92696a1089291c87a569a002a54e4ee0bce2e53b081182977c4c2374d8c752ee06521bcf53bc892ddcac0b0a231a6e8e83340c59116db0c607085aff6b654ba455169841452d1734970583732f20ce856ee2b4de92645b870eb9072a05fadcc9a88d9d956a508056e2edbba698c8ba17528be7ef236a273b96964b42ebe67f6668720b6effbfa195e898a15a37bc0633ed715f1b11ac9584212bd986ff9b299d6dcd674eea5b985dded78a868ed29ee2c7ec8d2ad68ef8ee43d14c422bf2fb3d1d08e26034c7661c930137e41a5b61c34a7361e6f0000000e636172646e6f3a35393737363530");
        var buffer = ByteBuffer.wrap(msg);
        Assert.assertEquals(AgentMessage.identify(buffer), AgentMessage.SSH_AGENT_IDENTITIES_ANSWER);
        var identitiesAnswer = IdentitiesAnswer.fromByteBuffer(buffer);
        Assert.assertFalse(buffer.hasRemaining());
        Assert.assertEquals(identitiesAnswer.getIdentities().size(), 1);
    }

    public static boolean runningFromIntelliJ() {
        String classPath = System.getProperty("java.class.path");
        return classPath.contains("idea_rt.jar");
    }

    @Test
    public void testParseAllPublicInUserFolder() throws Exception {
        if (!runningFromIntelliJ()) {
            throw new SkipException("Only interactive");
        }
        var userssh = Paths.get(System.getProperty("user.home"), ".ssh");
        Files.list(userssh).filter(e -> e.toString().endsWith(".pub")).map(SSHIdentity::from).forEach(System.out::println);
    }
}
