using N_m3u8DL_RE.Parser.Config;
using N_m3u8DL_RE.Common.Entity;
using N_m3u8DL_RE.Common.Enum;
using N_m3u8DL_RE.Common.Log;
using N_m3u8DL_RE.Common.Resource;
using N_m3u8DL_RE.Parser.Util;
using N_m3u8DL_RE.Parser.Constants;
using N_m3u8DL_RE.Common.Util;

namespace N_m3u8DL_RE.Parser.Extractor;

internal class HLSExtractor : IExtractor
{
    public ExtractorType ExtractorType => ExtractorType.HLS;

    private string M3u8Url = string.Empty;
    private string BaseUrl = string.Empty;
    private string M3u8Content = string.Empty;
    private bool MasterM3u8Flag = false;

    public ParserConfig ParserConfig { get; set; }

    //Chrome Ctrl+Shift+F 搜索关键字 playlistDecryptHandler 和 MOUFLON，在可疑的地方console.log()或者下断点(Source Overrides 替换js文件内容)
    //平台有多个播放器，如果这个房间没有触发逻辑就多试几个房间，断到了playlistDecryptHandler后就查看变量，key就在里面
    //chunk-fb8457ec7ca0302d78a3.js 搜索 this._playlistDecryptHandler = n，下断点，断到之后看右边的this._playlistDecryptHandler._knownKeyIds和this._playlistDecryptHandler._knownKeys
    //如果知道密钥的前缀，可以捕捉Heap Snapshot，然后保存Snapshot，用EmEditor配合正则表达式 "EQue.{12}" 去搜索

    //知道密钥以后，去找到使用密钥对应的代码：
    //Memory面板搜索密钥，点击密钥对象，查看Retainer，寻找可疑的方法，比如_decode()，展开以后看到prototype in Kn()，说明代码在Kn类里
    //Memory面板 Filter By Class 搜索Kn，展开__proto__，constructor，shared，script获取脚本名 https://img.doppiocdn.com/player/mmp/v2.1.3/chunk-fb8457ec7ca0302d78a3.js
    //Network面板搜索fb8457ec7ca0302d78a3，跳转到对应的代码文件，搜索class Kn
    Dictionary<string, string> ih = new Dictionary<string, string>
    {
        { "Zokee2OhPh9kugh4", "Quean4cai9boJa5a" },
        { "Zeechoej4aleeshi", "ubahjae7goPoodi6" },
        { "Ook7quaiNgiyuhai", "EQueeGh2kaewa3ch" }
    };

    public HLSExtractor(ParserConfig parserConfig)
    {
        this.ParserConfig = parserConfig;
        this.M3u8Url = parserConfig.Url ?? string.Empty;
        this.SetBaseUrl();
    }

    private void SetBaseUrl()
    {
        this.BaseUrl = !string.IsNullOrEmpty(ParserConfig.BaseUrl) ? ParserConfig.BaseUrl : this.M3u8Url;
    }

    /// <summary>
    /// 预处理m3u8内容
    /// </summary>
    public void PreProcessContent()
    {
        M3u8Content = M3u8Content.Trim();
        if (!M3u8Content.StartsWith(HLSTags.ext_m3u))
        {
            throw new Exception(ResString.badM3u8);
        }

        foreach (var p in ParserConfig.ContentProcessors)
        {
            if (p.CanProcess(ExtractorType, M3u8Content, ParserConfig))
            {
                M3u8Content = p.Process(M3u8Content, ParserConfig);
            }
        }
    }

    /// <summary>
    /// 预处理URL
    /// </summary>
    public string PreProcessUrl(string url)
    {
        foreach (var p in ParserConfig.UrlProcessors)
        {
            if (p.CanProcess(ExtractorType, url, ParserConfig))
            {
                url = p.Process(url, ParserConfig);
            }
        }

        return url;
    }

    private Task<List<StreamSpec>> ParseMasterListAsync()
    {
        MasterM3u8Flag = true;

        List<StreamSpec> streams = [];

        using StringReader sr = new StringReader(M3u8Content);
        string? line;
        bool expectPlaylist = false;
        StreamSpec streamSpec = new();

        while ((line = sr.ReadLine()) != null)
        {
            if (string.IsNullOrEmpty(line))
                continue;

            if (line.StartsWith(HLSTags.ext_x_stream_inf))
            {
                streamSpec = new();
                streamSpec.OriginalUrl = ParserConfig.OriginalUrl;
                var bandwidth = string.IsNullOrEmpty(ParserUtil.GetAttribute(line, "AVERAGE-BANDWIDTH")) ? ParserUtil.GetAttribute(line, "BANDWIDTH") : ParserUtil.GetAttribute(line, "AVERAGE-BANDWIDTH");
                streamSpec.Bandwidth = Convert.ToInt32(bandwidth);
                streamSpec.Codecs = ParserUtil.GetAttribute(line, "CODECS");
                streamSpec.Resolution = ParserUtil.GetAttribute(line, "RESOLUTION");

                var frameRate = ParserUtil.GetAttribute(line, "FRAME-RATE");
                if (!string.IsNullOrEmpty(frameRate))
                    streamSpec.FrameRate = Convert.ToDouble(frameRate);

                var audioId = ParserUtil.GetAttribute(line, "AUDIO");
                if (!string.IsNullOrEmpty(audioId))
                    streamSpec.AudioId = audioId;

                var videoId = ParserUtil.GetAttribute(line, "VIDEO");
                if (!string.IsNullOrEmpty(videoId))
                    streamSpec.VideoId = videoId;

                var subtitleId = ParserUtil.GetAttribute(line, "SUBTITLES");
                if (!string.IsNullOrEmpty(subtitleId))
                    streamSpec.SubtitleId = subtitleId;

                var videoRange = ParserUtil.GetAttribute(line, "VIDEO-RANGE");
                if (!string.IsNullOrEmpty(videoRange))
                    streamSpec.VideoRange = videoRange;

                // 清除多余的编码信息 dvh1.05.06,ec-3 => dvh1.05.06
                if (!string.IsNullOrEmpty(streamSpec.Codecs) && !string.IsNullOrEmpty(streamSpec.AudioId))
                {
                    streamSpec.Codecs = streamSpec.Codecs.Split(',')[0];
                }

                expectPlaylist = true;
            }
            else if (line.StartsWith(HLSTags.ext_x_media))
            {
                streamSpec = new();
                var type = ParserUtil.GetAttribute(line, "TYPE").Replace("-", "_");
                if (Enum.TryParse<MediaType>(type, out var mediaType))
                {
                    streamSpec.MediaType = mediaType;
                }

                // 跳过CLOSED_CAPTIONS类型（目前不支持）
                if (streamSpec.MediaType == MediaType.CLOSED_CAPTIONS)
                {
                    continue;
                }

                var url = ParserUtil.GetAttribute(line, "URI");

                /**
                 *    The URI attribute of the EXT-X-MEDIA tag is REQUIRED if the media
                      type is SUBTITLES, but OPTIONAL if the media type is VIDEO or AUDIO.
                      If the media type is VIDEO or AUDIO, a missing URI attribute
                      indicates that the media data for this Rendition is included in the
                      Media Playlist of any EXT-X-STREAM-INF tag referencing this EXT-
                      X-MEDIA tag.  If the media TYPE is AUDIO and the URI attribute is
                      missing, clients MUST assume that the audio data for this Rendition
                      is present in every video Rendition specified by the EXT-X-STREAM-INF
                      tag.

                      此处直接忽略URI属性为空的情况
                 */
                if (string.IsNullOrEmpty(url))
                {
                    continue;
                }

                url = ParserUtil.CombineURL(BaseUrl, url);
                streamSpec.Url = PreProcessUrl(url);

                var groupId = ParserUtil.GetAttribute(line, "GROUP-ID");
                streamSpec.GroupId = groupId;

                var lang = ParserUtil.GetAttribute(line, "LANGUAGE");
                if (!string.IsNullOrEmpty(lang))
                    streamSpec.Language = lang;

                var name = ParserUtil.GetAttribute(line, "NAME");
                if (!string.IsNullOrEmpty(name))
                    streamSpec.Name = name;

                var def = ParserUtil.GetAttribute(line, "DEFAULT");
                if (Enum.TryParse<Choise>(type, out var defaultChoise))
                {
                    streamSpec.Default = defaultChoise;
                }

                var channels = ParserUtil.GetAttribute(line, "CHANNELS");
                if (!string.IsNullOrEmpty(channels))
                    streamSpec.Channels = channels;

                var characteristics = ParserUtil.GetAttribute(line, "CHARACTERISTICS");
                if (!string.IsNullOrEmpty(characteristics))
                    streamSpec.Characteristics = characteristics.Split(',').Last().Split('.').Last();

                streams.Add(streamSpec);
            }
            else if (line.StartsWith('#'))
            {
                continue;
            }
            else if (expectPlaylist)
            {
                var url = ParserUtil.CombineURL(BaseUrl, line);
                streamSpec.Url = PreProcessUrl(url);
                expectPlaylist = false;
                streams.Add(streamSpec);
            }
        }

        return Task.FromResult(streams);
    }
    private Byte[] SHA256EncryptByte(string deseninstr)
    {
        using (var mySHA256 = System.Security.Cryptography.SHA256Managed.Create())
        {
            byte[] deseninbyte = System.Text.Encoding.UTF8.GetBytes(deseninstr);
            byte[] EncryptBytes = mySHA256.ComputeHash(deseninbyte);
            return EncryptBytes;
        }
    }
    private Byte[] Base64Decode(string data)
    {
        int missing_padding = data.Length % 4;
        int need_to_add_count = 4 - missing_padding;
        if (missing_padding != 0)
        {
            for (int i = 0; i < need_to_add_count; i++)
                data = data + '=';
        }
        return Convert.FromBase64String(data);
    }

    public static string Reverse(string text)
    {
        char[] array = text.ToCharArray();
        Array.Reverse(array);
        return new String(array);
    }

    private Task<Playlist> ParseListAsync()
    {
        // 标记是否已清除广告分片
        bool hasAd = false;
        ;
        bool allowHlsMultiExtMap = ParserConfig.CustomParserArgs.TryGetValue("AllowHlsMultiExtMap", out var allMultiExtMap) && allMultiExtMap == "true";
        if (allowHlsMultiExtMap)
        {
            Logger.WarnMarkUp($"[darkorange3_1]{ResString.allowHlsMultiExtMap}[/]");
        }
        
        using StringReader sr = new StringReader(M3u8Content);
        string? line;
        bool expectSegment = false;
        bool isEndlist = false;
        long segIndex = 0;
        bool isAd = false;
        long startIndex;

        Playlist playlist = new();
        List<MediaPart> mediaParts = [];

        // 当前的加密信息
        EncryptInfo currentEncryptInfo = new();
        if (ParserConfig.CustomMethod != null)
            currentEncryptInfo.Method = ParserConfig.CustomMethod.Value;
        if (ParserConfig.CustomeKey is { Length: > 0 }) 
            currentEncryptInfo.Key = ParserConfig.CustomeKey;
        if (ParserConfig.CustomeIV is { Length: > 0 })
            currentEncryptInfo.IV = ParserConfig.CustomeIV;
        // 上次读取到的加密行，#EXT-X-KEY:……
        string lastKeyLine = "";

        MediaPart mediaPart = new();
        MediaSegment segment = new();
        List<MediaSegment> segments = [];

        string pkey = "";
        Dictionary<string, int> part_url_dictionary = new Dictionary<string, int>();

        while ((line = sr.ReadLine()) != null)
        {
            if (string.IsNullOrEmpty(line))
                continue;

            // 只下载部分字节
            if (line.StartsWith(HLSTags.ext_x_byterange))
            {
                var p = ParserUtil.GetAttribute(line);
                var (n, o) = ParserUtil.GetRange(p);
                segment.ExpectLength = n;
                segment.StartRange = o ?? segments.Last().StartRange + segments.Last().ExpectLength;
                expectSegment = true;
            }
            else if (line.StartsWith(HLSTags.ext_x_playlist_type))
            {
                isEndlist = line.Trim().EndsWith("VOD");
            }
            // 国家地理去广告
            else if (line.StartsWith("#UPLYNK-SEGMENT"))
            {
                if (line.Contains(",ad"))
                    isAd = true;
                else if (line.Contains(",segment"))
                    isAd = false;
            }
            // 国家地理去广告
            else if (isAd)
            {
                continue;
            }
            // 解析定义的分段长度
            else if (line.StartsWith(HLSTags.ext_x_targetduration))
            {
                playlist.TargetDuration = Convert.ToDouble(ParserUtil.GetAttribute(line));
            }
            // 解析起始编号
            else if (line.StartsWith(HLSTags.ext_x_media_sequence))
            {
                segIndex = Convert.ToInt64(ParserUtil.GetAttribute(line));
                startIndex = segIndex;
            }
            // program date time
            else if (line.StartsWith(HLSTags.ext_x_program_date_time))
            {
                segment.DateTime = DateTime.Parse(ParserUtil.GetAttribute(line));
            }
            // 解析不连续标记，需要单独合并（timestamp不同）
            else if (line.StartsWith(HLSTags.ext_x_discontinuity))
            {
                // 修复YK去除广告后的遗留问题
                if (hasAd && mediaParts.Count > 0)
                {
                    segments = mediaParts[^1].MediaSegments;
                    mediaParts.RemoveAt(mediaParts.Count - 1);
                    hasAd = false;
                    continue;
                }
                // 常规情况的#EXT-X-DISCONTINUITY标记，新建part
                if (hasAd || segments.Count < 1) continue;
                
                mediaParts.Add(new MediaPart
                {
                    MediaSegments = segments,
                });
                segments = new();
            }
            // 解析KEY
            else if (line.StartsWith(HLSTags.ext_x_key))
            {
                // 如果KEY line相同则不再重复解析
                if (line != lastKeyLine)
                {
                    // 调用处理器进行解析
                    var parsedInfo = ParseKey(line);
                    currentEncryptInfo.Method = parsedInfo.Method;
                    currentEncryptInfo.Key = parsedInfo.Key;
                    currentEncryptInfo.IV = parsedInfo.IV;
                }
                lastKeyLine = line;
            }
            /*
            // 解析分片时长
            else if (line.StartsWith(HLSTags.extinf))
            {
                string[] tmp = ParserUtil.GetAttribute(line).Split(',');
                segment.Duration = Convert.ToDouble(tmp[0]);
                segment.Index = segIndex;
                // 是否有加密，有的话写入KEY和IV
                if (currentEncryptInfo.Method != EncryptMethod.NONE)
                {
                    segment.EncryptInfo.Method = currentEncryptInfo.Method;
                    segment.EncryptInfo.Key = currentEncryptInfo.Key;
                    segment.EncryptInfo.IV = currentEncryptInfo.IV ?? HexUtil.HexToBytes(Convert.ToString(segIndex, 16).PadLeft(32, '0'));
                }
                expectSegment = true;
                segIndex++;
            }
            */
            // m3u8主体结束
            else if (line.StartsWith(HLSTags.ext_x_endlist))
            {
                if (segments.Count > 0)
                {
                    mediaParts.Add(new MediaPart()
                    {
                        MediaSegments = segments
                    });
                }
                segments = new();
                isEndlist = true;
            }
            // #EXT-X-MAP
            else if (line.StartsWith(HLSTags.ext_x_map))
            {
                if (playlist.MediaInit == null || hasAd) 
                {
                    playlist.MediaInit = new MediaSegment()
                    {
                        Url = PreProcessUrl(ParserUtil.CombineURL(BaseUrl, ParserUtil.GetAttribute(line, "URI"))),
                        Index = -1, // 便于排序
                    };
                    if (line.Contains("BYTERANGE"))
                    {
                        var p = ParserUtil.GetAttribute(line, "BYTERANGE");
                        var (n, o) = ParserUtil.GetRange(p);
                        playlist.MediaInit.ExpectLength = n;
                        playlist.MediaInit.StartRange = o ?? 0L;
                    }
                    if (currentEncryptInfo.Method == EncryptMethod.NONE) continue;
                    // 有加密的话写入KEY和IV
                    playlist.MediaInit.EncryptInfo.Method = currentEncryptInfo.Method;
                    playlist.MediaInit.EncryptInfo.Key = currentEncryptInfo.Key;
                    playlist.MediaInit.EncryptInfo.IV = currentEncryptInfo.IV ?? HexUtil.HexToBytes(Convert.ToString(segIndex, 16).PadLeft(32, '0'));
                }
                // 遇到了其他的map，说明已经不是一个视频了，全部丢弃即可
                else
                {
                    if (segments.Count > 0)
                    {
                        mediaParts.Add(new MediaPart()
                        {
                            MediaSegments = segments
                        });
                    }
                    segments = new();
                    if (!allowHlsMultiExtMap)
                    {
                        isEndlist = true;
                        break;
                    }
                }
            }
            else if (line.StartsWith("#EXT-X-PART-INF")) continue;
            else if (line.StartsWith("#EXT-X-MOUFLON:PSCH"))
            {
                string[] splits = line.Split(':');
                pkey = splits[splits.Length - 1];
            }
            else if (line.StartsWith("#EXT-X-MOUFLON:URI"))
            {
                string part_url = line.Substring(19);
                if (!part_url.Contains("_part"))
                    continue;
                string[] splits_outer = part_url.Split('_');
                string encrypted_content = splits_outer[2];
                string encrypted_content_reversed = Reverse(encrypted_content);

                string t = ih[pkey];
                byte[] i = SHA256EncryptByte(t);
                byte[] n = Base64Decode(encrypted_content_reversed);

                byte[] s = new byte[n.Length];
                for (int x = 0; x < n.Length; x++)
                    s[x] = (byte)((int)n[x] ^ (int)i[x % i.Length]);
                string decode_content = System.Text.Encoding.UTF8.GetString(s);
                part_url = part_url.Replace(encrypted_content, decode_content);
                if (!part_url_dictionary.ContainsKey(part_url))
                {
                    string[] splits = part_url.Split('_');

                    string timestampCorrupted = splits[splits.Length - 2];
                    string[] splits2 = timestampCorrupted.Split('.');
                    string timestamp = splits2[0];
                    long timestampNumber = long.Parse(timestamp);

                    string partCorrupted = splits[splits.Length - 1];
                    string[] splits3 = partCorrupted.Split('.');
                    string part = splits3[0];
                    int partNumber = int.Parse(part.Replace("part", ""));

                    string streamIndex = splits[splits.Length - 4];
                    int streamIndexNumber = int.Parse(streamIndex);
                    /*
                    this.last_msn = streamIndexNumber;
                    this.last_part = partNumber;
                    if (!msn_max_part_dict.ContainsKey(streamIndexNumber))
                        msn_max_part_dict[streamIndexNumber] = 0;

                    if (partNumber > msn_max_part_dict[streamIndexNumber])
                        msn_max_part_dict[streamIndexNumber] = partNumber;
                    */
                    long timestampNumberAddPart = timestampNumber * 100 + partNumber;
                    DateTime partDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
                    partDateTime = partDateTime.AddSeconds(timestampNumberAddPart).ToLocalTime();

                    segment.Url = part_url;
                    segment.DateTime = partDateTime;
                    segment.Duration = Convert.ToDouble(2);
                    segment.Index = timestampNumberAddPart;
                    segments.Add(segment);
                    segment = new();

                    part_url_dictionary[part_url] = 0;
                    //Console.WriteLine(string.Format("HLSExtract parse part url:{0} timestampNumber:{1} partNumber:{2} Index:{3} partNumber:{4}", part_url, timestampNumber, partNumber, segment.Index, partNumber));
                }
            }
            /*
            // 评论行不解析
            else if (line.StartsWith('#')) continue;
            // 空白行不解析
            else if (line.StartsWith("\r\n")) continue;
            // 解析分片的地址
            else if (expectSegment)
            {
                var segUrl = PreProcessUrl(ParserUtil.CombineURL(BaseUrl, line));
                Console.WriteLine(string.Format("expectSegment segUrl:{0}", segUrl));
                segment.Url = segUrl;
                segments.Add(segment);
                segment = new();
                // YK的广告分段则清除此分片
                // 需要注意，遇到广告说明程序对上文的#EXT-X-DISCONTINUITY做出的动作是不必要的，
                // 其实上下文是同一种编码，需要恢复到原先的part上
                if (segUrl.Contains("ccode=") && segUrl.Contains("/ad/") && segUrl.Contains("duration="))
                {
                    segments.RemoveAt(segments.Count - 1);
                    segIndex--;
                    hasAd = true;
                }
                // YK广告(4K分辨率测试)
                if (segUrl.Contains("ccode=0902") && segUrl.Contains("duration="))
                {
                    segments.RemoveAt(segments.Count - 1);
                    segIndex--;
                    hasAd = true;
                }
                expectSegment = false;
            }
            */
        }

        // 直播的情况，无法遇到m3u8结束标记，需要手动将segments加入parts
        if (!isEndlist)
        {
            mediaParts.Add(new MediaPart()
            {
                MediaSegments = segments
            });
        }

        playlist.MediaParts = mediaParts;
        playlist.IsLive = !isEndlist;

        // 直播刷新间隔
        if (playlist.IsLive)
        {
            // 由于播放器默认从最后3个分片开始播放 此处设置刷新间隔为TargetDuration的2倍
            playlist.RefreshIntervalMs = (int)((playlist.TargetDuration ?? 5) * 2 * 1000);
        }

        return Task.FromResult(playlist);
    }

    private EncryptInfo ParseKey(string keyLine)
    {
        foreach (var p in ParserConfig.KeyProcessors)
        {
            if (p.CanProcess(ExtractorType, keyLine, M3u8Url, M3u8Content, ParserConfig))
            {
                // 匹配到对应处理器后不再继续
                return p.Process(keyLine, M3u8Url, M3u8Content, ParserConfig);
            }
        }

        throw new Exception(ResString.keyProcessorNotFound);
    }

    public async Task<List<StreamSpec>> ExtractStreamsAsync(string rawText)
    {
        this.M3u8Content = rawText;
        this.PreProcessContent();
        if (M3u8Content.Contains(HLSTags.ext_x_stream_inf))
        {
            Logger.Warn(ResString.masterM3u8Found);
            var lists = await ParseMasterListAsync();
            lists = lists.DistinctBy(p => p.Url).ToList();
            return lists;
        }

        var playlist = await ParseListAsync();
        return
        [
            new()
            {
                Url = ParserConfig.Url,
                Playlist = playlist,
                Extension = playlist.MediaInit != null ? "mp4" : "ts"
            }
        ];
    }

    private async Task LoadM3u8FromUrlAsync(string url)
    {
        // Logger.Info(ResString.loadingUrl + url);
        if (url.StartsWith("file:"))
        {
            var uri = new Uri(url);
            this.M3u8Content = File.ReadAllText(uri.LocalPath);
        }
        else if (url.StartsWith("http"))
        {
            try
            {
                (this.M3u8Content, url) = await HTTPUtil.GetWebSourceAndNewUrlAsync(url, ParserConfig.Headers);
            }
            catch (HttpRequestException) when (ParserConfig.OriginalUrl.StartsWith("http") && url != ParserConfig.OriginalUrl)
            {
                // 当URL无法访问时，再请求原始URL
                (this.M3u8Content, url) = await HTTPUtil.GetWebSourceAndNewUrlAsync(ParserConfig.OriginalUrl, ParserConfig.Headers);
            }
        }

        this.M3u8Url = url;
        this.SetBaseUrl();
        this.PreProcessContent();
    }

    /// <summary>
    /// 从Master链接中刷新各个流的URL
    /// </summary>
    /// <param name="lists"></param>
    /// <returns></returns>
    private async Task RefreshUrlFromMaster(List<StreamSpec> lists)
    {
        // 重新加载master m3u8, 刷新选中流的URL
        await LoadM3u8FromUrlAsync(ParserConfig.Url);
        var newStreams = await ParseMasterListAsync();
        newStreams = newStreams.DistinctBy(p => p.Url).ToList();
        foreach (var l in lists)
        {
            var match = newStreams.Where(n => n.ToShortString() == l.ToShortString()).ToList();
            if (match.Count == 0) continue;
            
            Logger.DebugMarkUp($"{l.Url} => {match.First().Url}");
            l.Url = match.First().Url;
        }
    }

    public async Task FetchPlayListAsync(List<StreamSpec> lists)
    {
        for (int i = 0; i < lists.Count; i++)
        {
            try
            {
                // 直接重新加载m3u8
                await LoadM3u8FromUrlAsync(lists[i].Url!);
            }
            catch (HttpRequestException) when (MasterM3u8Flag)
            {
                Logger.WarnMarkUp("Can not load m3u8. Try refreshing url from master url...");
                // 当前URL无法加载 尝试从Master链接中刷新URL
                await RefreshUrlFromMaster(lists);
                await LoadM3u8FromUrlAsync(lists[i].Url!);
            }

            var newPlaylist = await ParseListAsync();
            if (lists[i].Playlist?.MediaInit != null)
                lists[i].Playlist!.MediaParts = newPlaylist.MediaParts; // 不更新init
            else
                lists[i].Playlist = newPlaylist;

            if (lists[i].MediaType == MediaType.SUBTITLES)
            {
                var a = lists[i].Playlist!.MediaParts.Any(p => p.MediaSegments.Any(m => m.Url.Contains(".ttml")));
                var b = lists[i].Playlist!.MediaParts.Any(p => p.MediaSegments.Any(m => m.Url.Contains(".vtt") || m.Url.Contains(".webvtt")));
                if (a) lists[i].Extension = "ttml";
                if (b) lists[i].Extension = "vtt";
            }
            else
            {
                lists[i].Extension = lists[i].Playlist!.MediaInit != null ? "m4s" : "ts";
            }
        }
    }

    public async Task RefreshPlayListAsync(List<StreamSpec> streamSpecs)
    {
        await FetchPlayListAsync(streamSpecs);
    }
}