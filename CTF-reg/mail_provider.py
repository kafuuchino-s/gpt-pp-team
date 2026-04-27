"""
邮箱服务 - 通过 IMAP 收取 OTP 验证码
使用 catch-all 域名生成随机邮箱，通过 IMAP 从 QQ 邮箱收取转发的验证码
"""
import email
import email.message
import imaplib
import random
import re
import string
import time
import logging
import os
from email.header import decode_header
from email.utils import parsedate_to_datetime
from datetime import datetime

logger = logging.getLogger(__name__)


class MailProvider:
    """IMAP 邮箱提供者 (catch-all 域名 + QQ 邮箱 IMAP)"""
    _GLOBAL_CONSUMED_UIDS: dict[str, set[int]] = {}

    def __init__(self, imap_server: str, imap_port: int, email_addr: str, auth_code: str,
                 catch_all_domain: str = ""):
        self.imap_server = imap_server
        self.imap_port = imap_port
        self.email_addr = email_addr
        self.auth_code = auth_code
        self.catch_all_domain = catch_all_domain
        # 跨多次 wait_for_otp（含新建实例）保留“已消费”消息 UID，避免重复读取旧验证码
        global_key = f"{imap_server}:{imap_port}:{email_addr}".lower()
        self._consumed_uids = self._GLOBAL_CONSUMED_UIDS.setdefault(global_key, set())

    def _connect(self) -> imaplib.IMAP4_SSL:
        """建立 IMAP 连接并登录"""
        # 避免 IMAP 网络抖动导致单次调用长时间卡死
        conn = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, timeout=15)
        try:
            if getattr(conn, "sock", None):
                conn.sock.settimeout(15)
        except Exception:
            pass
        conn.login(self.email_addr, self.auth_code)
        return conn

    @staticmethod
    def _random_name() -> str:
        letters1 = "".join(random.choices(string.ascii_lowercase, k=5))
        numbers = "".join(random.choices(string.digits, k=random.randint(1, 3)))
        letters2 = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))
        return letters1 + numbers + letters2

    def create_mailbox(self) -> str:
        """生成随机 catch-all 邮箱地址，或复用指定邮箱"""
        # 如果设置了 _reuse_email，复用它
        if hasattr(self, '_reuse_email') and self._reuse_email:
            addr = self._reuse_email
            self._reuse_email = None  # 只复用一次
            logger.info(f"复用邮箱: {addr}")
            return addr

        conn = self._connect()
        conn.logout()

        if self.catch_all_domain:
            addr = f"{self._random_name()}@{self.catch_all_domain}"
        else:
            addr = self.email_addr

        logger.info(f"邮箱已创建: {addr} (IMAP 收件: {self.email_addr})")
        return addr

    @staticmethod
    def _decode_header_value(value: str) -> str:
        """解码 MIME Header，返回可读文本"""
        if not value:
            return ""
        parts = decode_header(value)
        out = []
        for chunk, charset in parts:
            if isinstance(chunk, bytes):
                out.append(chunk.decode(charset or "utf-8", errors="replace"))
            else:
                out.append(chunk)
        return "".join(out)

    @staticmethod
    def _decode_payload(msg: email.message.Message) -> str:
        """提取邮件正文"""
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body += payload.decode(charset, errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                body = payload.decode(charset, errors="replace")
        return body

    @staticmethod
    def _extract_otp(content: str) -> str | None:
        """从邮件内容中提取 OTP（优先语义匹配，避免误抓邮箱域名数字）"""
        text = (content or "").replace(" ", " ")

        # 1) 语义匹配：验证码上下文
        semantic_patterns = [
            r"(?:chatgpt|openai)[^\n\r]{0,100}?(?:code|验证码)[^\d]{0,24}(\d{6})",
            r"(?:verification\s*code|one[-\s]*time\s*code|code\s*is|验证码(?:为|是)?)[^\d]{0,24}(\d{6})",
            r">\s*(\d{6})\s*<",  # HTML 场景
        ]
        for pattern in semantic_patterns:
            m = re.search(pattern, text, flags=re.IGNORECASE)
            if m:
                return (m.group(1) or "").strip()

        # 2) 兜底匹配：先清理邮箱地址/URL，降低误命中概率
        scrubbed = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", " ", text)
        scrubbed = re.sub(r"https?://\S+", " ", scrubbed)
        candidates = re.findall(r"(?<![\w@.-])(\d{6})(?![\w@.-])", scrubbed)
        if candidates:
            # 取最后一个，通常模板中正文验证码在后半段
            return candidates[-1]
        return None


    def _match_recipient(self, msg: email.message.Message, target_email: str) -> bool:
        """检查邮件的收件人是否匹配目标地址"""
        if not target_email:
            return False

        target = target_email.lower().strip()
        headers_to_check = (
            "To",
            "Cc",
            "Delivered-To",
            "X-Original-To",
            "Envelope-To",
            "X-Envelope-To",
            "X-Forwarded-To",
            "X-Original-Recipient",
        )
        for header in headers_to_check:
            val = msg.get(header, "")
            if target in val.lower():
                return True

        # 有些转发场景收件头会被改写，兜底在全 header 中查找一次
        all_headers = "\n".join(f"{k}: {v}" for k, v in msg.items()).lower()
        if target in all_headers:
            return True

        return False

    @staticmethod
    def _message_timestamp(msg: email.message.Message) -> float | None:
        """解析邮件 Date 头为 unix 时间戳（秒）"""
        try:
            raw_date = msg.get("Date", "")
            if not raw_date:
                return None
            dt = parsedate_to_datetime(raw_date)
            return dt.timestamp()
        except Exception:
            return None

    @staticmethod
    def _search_uids(conn: imaplib.IMAP4_SSL, criteria: str) -> list[int]:
        """执行 UID SEARCH，返回 int UID 列表。异常时返回空列表。"""
        try:
            status, data = conn.uid("search", None, criteria)
            if status != "OK" or not data or not data[0]:
                return []
            out: list[int] = []
            for raw in data[0].split():
                try:
                    out.append(int(raw))
                except Exception:
                    continue
            return out
        except Exception:
            return []

    @staticmethod
    def _extract_internaldate_ts(fetch_meta) -> float | None:
        """从 UID FETCH 返回的元信息中提取 INTERNALDATE 时间戳。"""
        if not fetch_meta:
            return None
        try:
            text = fetch_meta.decode("utf-8", errors="replace") if isinstance(fetch_meta, bytes) else str(fetch_meta)
            m = re.search(r'INTERNALDATE\s+"([^"]+)"', text)
            if not m:
                return None
            # 示例: 02-Apr-2026 10:14:56 +0000
            dt = datetime.strptime(m.group(1), "%d-%b-%Y %H:%M:%S %z")
            return dt.timestamp()
        except Exception:
            return None


    def wait_for_otp(self, email_addr: str, timeout: int = 120, issued_after: float | None = None) -> str:
        """阻塞等待 OTP 验证码"""
        logger.info(f"等待 OTP 验证码 -> {email_addr} (最长 {timeout}s)...")
        issued_after_provided = issued_after is not None
        issued_after = issued_after if issued_after is not None else time.time()
        # 允许一定时钟偏差：若本机时间略快，避免把有效新邮件误判为旧邮件
        grace_seconds = 180.0

        start = time.time()
        processed_uids: set[int] = set()
        poll_round = 0
        last_progress_log_at = 0.0
        latest_fallback_otp: str | None = None
        latest_fallback_uid: int = 0
        latest_fallback_ts: float | None = None

        # 基线 UID：仅在显式提供 issued_after 时启用。
        # 作用：避免本轮误抓历史旧邮件（常见于转发邮箱堆积）。
        baseline_uid = 0
        if issued_after_provided:
            conn0 = None
            try:
                conn0 = self._connect()
                conn0.select("INBOX")
                all_uids = self._search_uids(conn0, "ALL")
                if all_uids:
                    baseline_uid = max(all_uids)
                    logger.info(f"OTP 轮询基线 UID: {baseline_uid}")
            except Exception as e:
                logger.debug(f"初始化 OTP 基线 UID 失败: {e}")
            finally:
                if conn0 is not None:
                    try:
                        conn0.logout()
                    except Exception:
                        pass

        relax_baseline_after = max(10, int(os.getenv("OTP_RELAX_BASELINE_AFTER", "25")))

        while time.time() - start < timeout:
            conn = None
            try:
                poll_round += 1
                conn = self._connect()
                conn.select("INBOX")

                # Fast path:
                # 对“精确目标邮箱”的最近邮件，先只抓 header 做一次轻量检查。
                # 这样可以绕过部分转发/正文延迟/IMAP 索引异常场景下的 full-body 解析不稳定。
                exact_uid_candidates = []
                for query in (
                    f'(UNSEEN TO "{email_addr}")',
                    f'(TO "{email_addr}")',
                ):
                    exact_uid_candidates.extend(self._search_uids(conn, query))
                if exact_uid_candidates:
                    for uid in sorted(set(exact_uid_candidates), reverse=True)[:8]:
                        if uid in self._consumed_uids:
                            continue
                        if baseline_uid and uid <= baseline_uid:
                            elapsed = time.time() - start
                            if elapsed < relax_baseline_after:
                                continue
                        status, msg_data = conn.uid(
                            "fetch",
                            str(uid),
                            "(INTERNALDATE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC DELIVERED-TO X-ORIGINAL-TO ENVELOPE-TO X-FORWARDED-TO SUBJECT)])",
                        )
                        if status != "OK" or not msg_data:
                            continue
                        raw = b""
                        fetch_meta = b""
                        for part in msg_data:
                            if isinstance(part, tuple):
                                if not fetch_meta:
                                    fetch_meta = part[0]
                                raw += part[1]
                        if not raw:
                            continue
                        header_msg = email.message_from_bytes(raw)
                        if not self._match_recipient(header_msg, email_addr):
                            continue
                        subject = self._decode_header_value(header_msg.get("Subject", ""))
                        otp = self._extract_otp(subject)
                        if not otp:
                            continue
                        msg_ts = self._extract_internaldate_ts(fetch_meta) or self._message_timestamp(header_msg)
                        if msg_ts is not None:
                            if baseline_uid and uid > baseline_uid:
                                if msg_ts + 86400 < issued_after:
                                    continue
                            elif msg_ts + grace_seconds < issued_after:
                                continue
                        processed_uids.add(uid)
                        self._consumed_uids.add(uid)
                        logger.info(f"收到 OTP(标题快速路径): {otp}")
                        return otp

                # QQ IMAP / 转发邮箱偶发存在搜索索引延迟，不能完全依赖单一 SEARCH 条件。
                # 这里把“精确目标邮箱”与“最近一批邮件”都纳入候选，随后在 Python 侧做更严格过滤。
                search_groups: list[tuple[str, list[int]]] = []
                search_groups.append(
                    ("exact_to_unseen", self._search_uids(conn, f'(UNSEEN TO "{email_addr}")'))
                )
                search_groups.append(
                    ("exact_to_any", self._search_uids(conn, f'(TO "{email_addr}")'))
                )
                search_groups.append(
                    ("openai_unseen", self._search_uids(conn, '(UNSEEN FROM "openai")'))
                )
                openai_any = self._search_uids(conn, '(FROM "openai")')
                if openai_any:
                    search_groups.append(("openai_any", openai_any[-120:]))
                all_recent = self._search_uids(conn, "ALL")
                if all_recent:
                    search_groups.append(("all_recent", all_recent[-160:]))

                uid_candidates: list[int] = []
                seen_uid_candidates: set[int] = set()
                for _reason, uids in search_groups:
                    for uid in uids or []:
                        if uid in seen_uid_candidates:
                            continue
                        seen_uid_candidates.add(uid)
                        uid_candidates.append(uid)

                if uid_candidates:
                    # 去重后按 UID 倒序（优先最新邮件），并限制每轮最多解析 40 封
                    uid_list = sorted(uid_candidates, reverse=True)[:60]
                    for uid in uid_list:
                        if uid in self._consumed_uids:
                            continue
                        if uid in processed_uids:
                            continue
                        if baseline_uid and uid <= baseline_uid:
                            # 显式 issued_after 模式下，默认跳过轮询开始前已存在的旧邮件。
                            # 但若长时间收不到新邮件，则放宽一次，回看最近邮件避免“邮件系统未新建 UID 但验证码已更新”的情况。
                            elapsed = time.time() - start
                            if elapsed < relax_baseline_after:
                                continue

                        # 使用 BODY.PEEK 避免 fetch 动作改变 Seen 状态，减少轮询扰动
                        status, msg_data = conn.uid("fetch", str(uid), "(INTERNALDATE BODY.PEEK[])")
                        if status != "OK":
                            continue
                        if not msg_data or not isinstance(msg_data[0], tuple) or len(msg_data[0]) < 2:
                            continue

                        fetch_meta = msg_data[0][0] if isinstance(msg_data[0], tuple) and len(msg_data[0]) >= 1 else b""
                        internal_ts = self._extract_internaldate_ts(fetch_meta)
                        raw = msg_data[0][1]
                        msg = email.message_from_bytes(raw)

                        # 识别发件人（优先 OpenAI，但不过度严格）
                        from_val = self._decode_header_value(msg.get("From", ""))
                        is_openai_sender = "openai" in from_val.lower()

                        # 确认是发给目标地址的
                        recipient_matched = self._match_recipient(msg, email_addr)
                        # 兜底：当直接收件箱模式（非 catch-all）且收件头被转发链改写时，
                        # 允许继续从 OpenAI 邮件中提取 OTP，避免“明明收到邮件但程序抓不到”。
                        if not recipient_matched:
                            if self.catch_all_domain:
                                processed_uids.add(uid)
                                continue
                            if email_addr.strip().lower() != (self.email_addr or "").strip().lower():
                                processed_uids.add(uid)
                                continue

                        subject = self._decode_header_value(msg.get("Subject", ""))
                        body = self._decode_payload(msg)
                        # 非 OpenAI 发件人时，做关键词过滤，避免误抓其它业务邮件 6 位数字
                        if not is_openai_sender:
                            hint_text = f"{subject}\n{body}"
                            if not re.search(
                                r"(openai|chatgpt|verification|one[\s-]?time|otp|验证码|code)",
                                hint_text,
                                flags=re.IGNORECASE,
                            ):
                                processed_uids.add(uid)
                                continue
                        otp = self._extract_otp(f"{subject}\n{body}")
                        if not otp:
                            # 新邮件刚到达时，正文/主题偶发还未完全就绪；如果这是目标收件人或 OpenAI 发件人，
                            # 不要立刻永久标记为 processed，允许后续轮询再次读取。
                            if not recipient_matched and not is_openai_sender:
                                processed_uids.add(uid)
                            continue
                        if otp:
                            # 防误抓：避免把目标邮箱中的 6 位数字（如域名 123456）当作验证码
                            email_digits = re.sub(r"\D", "", (email_addr or ""))
                            inbox_digits = re.sub(r"\D", "", (self.email_addr or ""))
                            domain_digits = re.sub(r"\D", "", (self.catch_all_domain or ""))
                            if (otp and ((email_digits and otp in email_digits) or (inbox_digits and otp in inbox_digits) or (domain_digits and otp in domain_digits))):
                                logger.debug(f"跳过疑似邮箱数字误命中 OTP: code={otp} email={email_addr}")
                                continue
                            msg_ts = internal_ts or self._message_timestamp(msg)
                            if msg_ts is not None and otp:
                                if uid > latest_fallback_uid:
                                    latest_fallback_uid = uid
                                    latest_fallback_otp = otp
                                    latest_fallback_ts = msg_ts
                            if msg_ts is not None:
                                # 关键修复：当启用了 baseline_uid（即仅消费“轮询开始后新增 UID”）时，
                                # 不再用 Date/INTERNALDATE 做严格时间裁剪。
                                # 原因：转发链路里 Date 头经常滞后/错乱，导致“明明是本轮新邮件却被当作旧邮件”。
                                if baseline_uid and uid > baseline_uid:
                                    # 仅保留一个极宽松兜底，避免异常脏数据（例如特别久远的历史邮件）
                                    if msg_ts + 86400 < issued_after:
                                        logger.debug(
                                            f"跳过异常旧邮件 uid={uid} ts={msg_ts:.0f} << issued_after={issued_after:.0f}"
                                        )
                                        # 记录兜底候选，超时时可回退尝试
                                        if uid > latest_fallback_uid:
                                            latest_fallback_uid = uid
                                            latest_fallback_otp = otp
                                            latest_fallback_ts = msg_ts
                                        continue
                                else:
                                    if msg_ts + grace_seconds < issued_after:
                                        logger.debug(
                                            f"跳过旧 OTP 邮件 uid={uid} ts={msg_ts:.0f} < issued_after={issued_after:.0f}"
                                        )
                                        # 记录兜底候选，超时时可回退尝试
                                        if uid > latest_fallback_uid:
                                            latest_fallback_uid = uid
                                            latest_fallback_otp = otp
                                        continue
                            processed_uids.add(uid)
                            self._consumed_uids.add(uid)
                            # 防止极端情况下 set 无限增长
                            if len(self._consumed_uids) > 5000:
                                keep = sorted(self._consumed_uids)[-2500:]
                                self._consumed_uids.clear()
                                self._consumed_uids.update(keep)
                            logger.info(f"收到 OTP: {otp}")
                            return otp
            except Exception as e:
                logger.warning(f"IMAP 轮询异常: {e}")
            finally:
                if conn is not None:
                    try:
                        conn.logout()
                    except Exception:
                        pass

            # 每 30s 打一条进度日志，避免“看起来卡住”
            now = time.time()
            if now - last_progress_log_at >= 30:
                elapsed = int(now - start)
                logger.info(
                    f"OTP 轮询中: 已等待 {elapsed}s, 轮询 {poll_round} 次, 已检查邮件 {len(processed_uids)} 封"
                )
                last_progress_log_at = now
            time.sleep(5)

        allow_stale_fallback = str(os.getenv('OTP_ALLOW_STALE_FALLBACK', '1')).lower() in (
            '1', 'true', 'yes', 'on'
        )
        fallback_max_age = max(300, int(os.getenv('OTP_FALLBACK_MAX_AGE', '10800')))
        if allow_stale_fallback and latest_fallback_otp and latest_fallback_ts is not None:
            age = max(0, int(time.time() - latest_fallback_ts))
            if age <= fallback_max_age:
                logger.warning(
                    f"等待新 OTP 超时，回退使用最近候选验证码: uid={latest_fallback_uid} age={age}s code={latest_fallback_otp}"
                )
                return latest_fallback_otp
            logger.warning(f"回退 OTP 已过期(age={age}s > {fallback_max_age}s)，不再使用")

        raise TimeoutError(f"等待 OTP 超时 ({timeout}s)")
