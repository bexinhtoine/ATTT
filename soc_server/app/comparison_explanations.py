"""Feature comparisons describe this deployment, not untested product claims."""
from pathlib import Path
import json
import re
import xml.etree.ElementTree as ET

FEATURE_GUIDES = {
 'dashboard': ('Theo dõi tình hình chung', 'Đếm log, cảnh báo, máy và hồ sơ trong CSDL SOC.', 'Tổng hợp số liệu của bản xuất Elastic qua API.', 'Tổng hợp số liệu của bản xuất Wazuh qua API.', 'SOC đang xem toàn CSDL, hai bản xuất ngoài chỉ có bộ log đã chọn. Không so trực tiếp hai tổng khác phạm vi.'),
 'logs': ('Thu thập và tìm log', 'Agent đọc Windows hoặc Linux, chuẩn hóa rồi lưu log và nội dung gốc.', 'Trong lượt này, nhận log đã chuẩn hóa do SOC chuyển tiếp và lập chỉ mục để tìm kiếm.', 'Trong lượt này, nhận dữ liệu SOC chuyển tiếp qua bộ thu log, bộ phân tích và bộ lưu tìm kiếm.', 'Cùng bộ log chứng minh đường chuyển dữ liệu; chưa so được chất lượng bộ đọc log độc lập của ba sản phẩm.'),
 'alerts': ('Tạo cảnh báo từ hành vi', 'Python kiểm tra từng sự kiện, đếm hoặc kiểm tra chuỗi; các log liên quan có thể gộp vào một cảnh báo.', 'Luật truy vấn, luật đếm và luật chuỗi EQL chạy trong Elastic; xuất cảnh báo của chính Elastic.', 'Bộ giải mã đọc trường dữ liệu; luật XML kiểm tra từng sự kiện hoặc tương quan; có thêm luật tiếp nhận và luật có sẵn.', 'Xem luật nào có cảnh báo và điều kiện thực tế. Số cảnh báo nhiều hơn có thể do cách gộp hoặc luật phụ, chưa phải độ chính xác cao hơn.'),
 'agents': ('Quản lý máy gửi dữ liệu', 'Có đăng ký agent, khóa xác thực, tín hiệu liên lạc định kỳ và thông tin máy.', 'Bản xuất chỉ liệt kê máy xuất hiện trong log chuyển tiếp; chưa kiểm thử agent Elastic độc lập trong lượt này.', 'Bản xuất chỉ liệt kê máy xuất hiện trong log chuyển tiếp; chưa kiểm thử agent Wazuh độc lập trong lượt này.', 'Máy xuất hiện trong log không đồng nghĩa đã cài agent của nền tảng đó. Chỉ SOC có bằng chứng quản lý agent trong ứng dụng này.'),
 'rules': ('Cách luật nhận diện hành vi', 'Điều kiện trong CSDL: mã sự kiện, nguồn, hành vi; luật đếm dùng thời gian sự kiện và luật chuỗi nối các sự kiện liên quan.', 'Luật query kiểm tra điều kiện; threshold đếm theo nhóm; EQL kiểm tra chuỗi. Bản cấu hình lab dùng thời gian tiếp nhận cho các luật đếm.', 'Luật XML lọc trường và liên kết luật trước đó; frequency/timeframe cấu hình số lần và thời gian; same_field/different_field liên kết các giá trị.', 'Cùng tên R01–R21 chưa có nghĩa điều kiện tương đương. Xem bảng dưới để đối chiếu nguồn log, ngưỡng, thời gian và cách đếm tài khoản.'),
 'incidents': ('Tổ chức và theo dõi điều tra', 'Đã thử tạo hồ sơ từ nhiều cảnh báo, lưu lý do liên kết, người phụ trách, ghi chú và lịch sử.', 'Chưa thu và xác minh hồ sơ sự cố của Elastic trong bản tích hợp này.', 'Chưa thu và xác minh hồ sơ sự cố của Wazuh trong bản tích hợp này.', 'Có thể xác nhận chức năng SOC đã thử. Chưa có bằng chứng tương ứng để xếp hạng khả năng quản lý sự cố của ba sản phẩm.'),
 'kb': ('Lưu bài học và hướng dẫn xử lý', 'Lưu bài viết, tạo bản nháp từ phân tích và duyệt trước khi dùng làm tài liệu tham khảo.', 'Chưa thu và xác minh chức năng tri thức của Elastic trong lượt thử.', 'Chưa thu và xác minh chức năng tri thức của Wazuh trong lượt thử.', 'Chưa tích hợp nghĩa là chưa có kết quả trong dự án, không có nghĩa sản phẩm không cung cấp chức năng tương ứng.'),
 'reports': ('Báo cáo và thống kê', 'Giao diện lọc theo thời gian, tổng hợp và vẽ biểu đồ trên dữ liệu SOC.', 'Bản xuất chứa thống kê log, cảnh báo và số luật có cảnh báo của bộ chung.', 'Bản xuất chứa thống kê log, cảnh báo và số luật có cảnh báo của bộ chung.', 'Hai nguồn ngoài mới có thống kê đã xuất. Chưa kiểm thử đầy đủ việc lập PDF, lập lịch hoặc xuất báo cáo trên giao diện gốc.'),
 'ip_reputation': ('Bổ sung thông tin về IP', 'Người phân tích lưu đánh giá IP nội bộ để bổ sung bối cảnh; việc lưu không tự chặn kết nối.', 'Chưa thu và xác minh tra cứu uy tín IP của Elastic trong lượt thử.', 'Chưa thu và xác minh tra cứu uy tín IP của Wazuh trong lượt thử.', 'Chỉ đối chiếu phần đã triển khai và có bằng chứng. Chưa đo độ đúng của nguồn đánh giá IP hay mức cập nhật thông tin.'),
 'operations': ('Theo dõi hoạt động hệ thống', 'Hiển thị công việc kiểm tra luật và phân tích, trạng thái, lỗi và số lần thử lại.', 'Bản xuất lấy trạng thái dịch vụ từ API tại lúc thu kết quả.', 'Bản xuất lấy trạng thái cụm lưu trữ từ API tại lúc thu kết quả.', 'Một công việc xử lý log và trạng thái cụm dịch vụ là hai đối tượng khác nhau. Cần thử cùng tải và cùng loại lỗi để so độ bền.'),
}


def feature_guide(feature, results):
    title, soc, elastic, wazuh, conclusion = FEATURE_GUIDES[feature]
    descriptions = dict(soc=soc, elastic=elastic, wazuh=wazuh)
    return dict(title=title, conclusion=conclusion, columns={key: dict(
        description=descriptions[key], scope=result.get('scope', 'Chưa có phạm vi dữ liệu'),
        time=result.get('collected_at', 'Chưa ghi nhận'), status=result['status'])
        for key, result in results.items()})


def _read(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def _condition_text(cond):
    names = {'source': 'Nguồn log', 'event_id': 'Mã sự kiện', 'action': 'Hành vi',
             'category': 'Nhóm hoạt động', 'outcome': 'Kết quả', 'user_in': 'Tài khoản',
             'extra': 'Thông tin bổ sung'}
    meanings = {'windows.security': 'nhật ký an ninh Windows', 'journald': 'nhật ký hệ thống Linux',
                'windows.system': 'nhật ký hệ thống Windows', 'windows.application': 'nhật ký ứng dụng Windows',
                'linux.syslog': 'nhật ký hệ thống Linux', 'agent.health': 'thông báo tình trạng bộ thu log',
                'linux.auth': 'nhật ký xác thực Linux', 'logon_failed': 'đăng nhập thất bại',
                'logon_success': 'đăng nhập thành công', 'invalid_user': 'tên tài khoản không tồn tại',
                'audit_log_cleared': 'xóa nhật ký kiểm toán', 'user_created': 'tạo tài khoản',
                'audit_policy_changed': 'thay đổi chính sách kiểm toán', 'failure': 'thất bại', 'web': 'truy cập web',
                'member_added_to_privileged_group': 'thêm thành viên vào nhóm đặc quyền',
                'user_added_to_privileged_group': 'thêm người dùng vào nhóm đặc quyền',
                'scheduled_task_created': 'tạo tác vụ theo lịch', 'event_log_cleared': 'xóa nhật ký',
                'log_channel_reset': 'đặt lại kênh nhật ký', 'sudo_failed': 'dùng sudo thất bại',
                'sudo_auth_failure': 'xác thực sudo thất bại', 'su_failed': 'chuyển người dùng bằng su thất bại',
                'ssh_accepted': 'SSH chấp nhận đăng nhập', 'web_suspicious_request': 'yêu cầu web đáng ngờ',
                'web_scanner_detected': 'dấu hiệu công cụ quét web', 'segfault': 'lỗi truy cập bộ nhớ',
                'oom_kill': 'dừng tiến trình vì thiếu bộ nhớ', 'service_crashed': 'dịch vụ gặp lỗi',
                'unexpected_shutdown': 'tắt máy bất thường', 'application_crash': 'ứng dụng gặp lỗi',
                'powershell_suspicious_script': 'nội dung PowerShell đáng ngờ'}
    text = []
    for key, value in cond.items():
        if key in ('precondition', 'trigger', 'min_count', 'join_fields', 'scope_host'):
            continue
        if key == 'extra' and isinstance(value, dict) and 'LogonType' in value:
            text.append('Kiểu đăng nhập 10: truy cập màn hình Windows từ xa')
            continue
        values = value if isinstance(value, list) else [value]
        rendered = ' hoặc '.join(meanings.get(str(v), str(v)) for v in values)
        text.append(f"{names.get(key, key)}: {rendered}")
    return '; '.join(text) + '.' if text else 'Xem điều kiện chi tiết bên dưới.'


def rule_definitions(soc_rules, run_id=None):
    root = Path(__file__).resolve().parents[2]
    artifacts = root / 'docs/kiem_thu_toan_bo_SOC/lam_lai_21_luat'
    exported = _read(artifacts / 'elastic_rules_new.json') or []
    elastic = {r.get('name', '').split()[0]: r for r in exported
               if r.get('name') and (not run_id or run_id in r.get('tags', []))}
    try:
        tree = ET.parse(artifacts / 'wazuh_new_rules.xml').getroot()
        marker = tree.find("rule/field[@name='soc_test']")
        wazuh = {r.attrib['id']: r for r in tree.findall('rule')} if (
            not run_id or (marker is not None and marker.text == '^' + run_id + '_v2$')) else {}
    except (OSError, ET.ParseError):
        wazuh = {}
    result = {}
    match_text = {
        'R01': 'Tìm hành vi xóa nhật ký kiểm toán đã được SOC nhận dạng.',
        'R02': 'Tìm hành vi xóa hoặc đặt lại kênh nhật ký.',
        'R03': 'Tìm hành vi tạo tài khoản với nguồn nhật ký an ninh Windows.',
        'R04': 'Tìm hành vi thêm tài khoản vào nhóm đặc quyền.',
        'R05': 'So mã sự kiện cài dịch vụ: 7045, 4697 hoặc 601.',
        'R06': 'Tìm hành vi tạo tác vụ định thời; không lọc riêng nguồn Security trong truy vấn này.',
        'R07': 'Tìm hành vi thay đổi chính sách kiểm toán đã được chuẩn hóa.',
        'R08': 'Tìm hành vi tạo người dùng trong nhật ký hệ thống hoặc xác thực Linux.',
        'R09': 'Tìm lỗi dùng sudo, lỗi xác thực sudo hoặc lỗi chuyển người dùng bằng su.',
        'R10': 'Tìm đăng nhập SSH được chấp nhận và tài khoản là root.',
        'R11': 'Tìm yêu cầu web đáng ngờ hoặc dấu hiệu công cụ quét web.',
        'R12': 'Tìm lỗi bộ nhớ, tiến trình, nhân hệ điều hành, dịch vụ hoặc tắt máy bất thường theo các nhãn trong cấu hình.',
        'R13': 'So mã 4740, 644 hoặc 539 trong nhật ký Security của Windows.',
        'R14': 'Tìm hành vi có nội dung PowerShell đáng ngờ đã được bộ đọc đánh dấu.',
        'R15': 'Chọn đăng nhập thất bại từ nhật ký xác thực hoặc hệ thống Linux.',
        'R16': 'Chọn đăng nhập thất bại trong nhật ký Security Windows.',
        'R17': 'Chọn đăng nhập thất bại hoặc tên tài khoản không tồn tại.',
        'R19': 'Chọn hành vi web_not_found, nghĩa là yêu cầu web không tìm thấy trang.',
        'R20': 'Chọn hành vi tên tài khoản không tồn tại.',
        'R21': 'Tìm đăng nhập thành công có kiểu đăng nhập 10, tức phiên tương tác từ xa.'
    }
    for rule in soc_rules:
        code = rule.code
        if not re.fullmatch(r'R\d\d', code or ''):
            continue
        cond = rule.conditions_dict
        description = _condition_text(cond)
        grouping = {'src_ip': 'IP nguồn', 'user_name': 'tài khoản', 'host': 'máy'}.get(rule.group_by, rule.group_by)
        if rule.rule_type == 'threshold':
            item = 'tên tài khoản khác nhau' if rule.distinct_field == 'user_name' else 'sự kiện phù hợp'
            description += f' Đếm ít nhất {rule.threshold_count} {item} trong {rule.window_seconds} giây; nhóm theo {grouping}, mặc định giới hạn cùng máy.'
        elif rule.rule_type == 'sequence':
            description = (f"Ít nhất {cond.get('min_count', 3)} lần theo điều kiện trước, rồi có sự kiện kích hoạt trong {rule.window_seconds} giây. "
                           'Mặc định cùng máy, tài khoản và IP. Trước: ' + _condition_text(cond.get('precondition', {})) +
                           ' Sau: ' + _condition_text(cond.get('trigger', {})))
        else:
            description += ' Một sự kiện phù hợp là đủ.'
        result[code] = {'soc': dict(explanation=description, origin='Cấu hình SOC đang lưu trong CSDL; có thể được chỉnh sau lượt thử.',
                                  config=dict(type=rule.rule_type, conditions=cond, threshold=rule.threshold_count,
                                              window_seconds=rule.window_seconds, group_by=rule.group_by, distinct_field=rule.distinct_field))}
        er = elastic.get(code)
        ec = {k: er[k] for k in ('rule_id','type','query','threshold','timestamp_override','interval','from','to') if k in er} if er else None
        if er:
            if er['type'] == 'threshold':
                threshold = er.get('threshold', {})
                explain = match_text.get(code, '') + f" Đếm ít nhất {threshold.get('value')} sự kiện theo máy và IP."
                if threshold.get('cardinality'):
                    explain += ' R17 còn yêu cầu ít nhất 5 tên tài khoản khác nhau.'
                explain += f" Chạy mỗi {er.get('interval')}; truy vấn từ {er.get('from')} đến {er.get('to')}, dùng {er.get('timestamp_override', 'thời gian mặc định')}. Khoảng này khác cửa sổ theo thời gian gốc của SOC."
            elif er['type'] == 'eql':
                explain = 'Chuỗi EQL: cùng máy, tài khoản và IP; ba lần đăng nhập thất bại rồi thành công trong tối đa 10 phút.'
            else:
                explain = match_text.get(code, 'Truy vấn điều kiện trên các trường đã chuẩn hóa.') + ' Một bản ghi phù hợp có thể sinh cảnh báo.'
        else:
            explain = 'Chưa có tệp cấu hình phù hợp với lượt thử để đối chiếu.'
        result[code]['elastic'] = dict(explanation=explain, origin='Cấu hình Elastic đã xuất trong lượt thử, không phải luật mặc định của mọi bản cài.', config=ec)
        wr = wazuh.get(str(100700 + int(code[1:])))
        wc = dict(wr.attrib, conditions=[dict(tag=e.tag, text=e.text, **e.attrib) for e in wr]) if wr is not None else None
        if wr is not None:
            if wr.get('frequency'):
                explain = match_text.get(code, '') + f" Luật XML cấu hình frequency={wr.get('frequency')} (số lần) và timeframe={wr.get('timeframe')} giây; liên kết dữ liệu cùng máy và IP."
                if code == 'R17':
                    explain = f"Cấu hình 5 lần trong 300 giây, cùng máy và IP. Chỉ liên kết nhánh SSH thất bại 100740 và yêu cầu khác tài khoản bằng different_field. Cần kiểm chứng tương đương với đếm tên duy nhất của SOC/Elastic."
                if code == 'R18':
                    explain += ' Sự kiện hiện tại phải là đăng nhập thành công; các lần trước khớp luật SSH thất bại, cùng tài khoản.'
            else:
                explain = match_text.get(code, 'Kiểm tra các trường sau giải mã.') + ' Luật XML so các trường trong dữ liệu chuyển tiếp; một bản ghi phù hợp là đủ. Xem danh sách trường bên dưới để đối chiếu chính xác.'
        else:
            explain = 'Chưa có tệp cấu hình phù hợp với lượt thử để đối chiếu.'
        result[code]['wazuh'] = dict(explanation=explain, origin='Cấu hình Wazuh đã xuất trong lượt thử; số lần thực tế còn phụ thuộc cơ chế tương quan.', config=wc)
    return result


def display_value(field, value):
    if value is None:
        return 'Chưa có thông tin'
    if field == 'enabled':
        return 'Đang bật' if value else 'Đang tắt'
    labels = {
        'match': 'Kiểm tra từng sự kiện', 'query': 'Truy vấn điều kiện',
        'threshold': 'Đếm theo ngưỡng', 'sequence': 'Kiểm tra chuỗi', 'eql': 'Kiểm tra chuỗi EQL',
        'Wazuh XML match': 'Kiểm tra từng sự kiện bằng XML',
        'Wazuh XML correlation': 'Liên kết nhiều sự kiện bằng XML',
        'Native alert stored': 'Đã lưu cảnh báo của nền tảng',
        'logon_failed': 'Đăng nhập thất bại', 'logon_success': 'Đăng nhập thành công',
        'invalid_user': 'Tên người dùng không tồn tại', 'user_created': 'Tạo tài khoản',
        'native level': 'Cấp độ riêng của Wazuh', 'clean': 'Chưa đánh dấu nguy cơ',
    }
    text = str(value)
    if text in labels:
        return labels[text]
    if field == 'title':
        return re.sub(r' native command lab$', ' · Luật của bài thử', text)
    return value


RULE_DIFFERENCES = {
 'R01': 'SOC so nguồn Security và mã 1102/517; hai cấu hình ngoài nhận hành vi xóa nhật ký đã chuẩn hóa. Đây là khác điều kiện đầu vào, dù cùng có cảnh báo trong lượt này.',
 'R06': 'SOC yêu cầu nguồn Security và hành vi tạo tác vụ; cấu hình ngoài lọc hành vi tạo tác vụ. Cần thử log khác nguồn để đánh giá chênh lệch.',
 'R07': 'SOC so mã 4719/612 trong Security; hai cấu hình ngoài lọc hành vi thay đổi chính sách. Luật của lượt lab không hoàn toàn giống điều kiện SOC.',
 'R12': 'Danh sách lỗi vận hành trong ba cấu hình có khác tên hành vi. Cần kiểm tra từng loại lỗi trước khi kết luận khả năng phát hiện tương đương.',
 'R17': 'SOC/Elastic nhận cả đăng nhập thất bại và tên không tồn tại; Wazuh trong cấu hình này nối nhánh SSH thất bại và dùng điều kiện khác tài khoản. Đây là điểm cần kiểm tra khi tìm nguyên nhân Wazuh chưa cảnh báo, chưa phải nguyên nhân đã được xác nhận.',
 'R18': 'SOC đối chiếu các lần thất bại và thành công theo thời gian sự kiện. Elastic dùng chuỗi EQL; Wazuh nối luật SSH thất bại với thành công. Phạm vi nguồn và thời gian cần đối chiếu.',
 'R19': 'SOC đếm mọi log web có kết quả thất bại; các cấu hình ngoài của lượt thử lọc hành vi web_not_found. Không đồng nhất tập yêu cầu web thất bại với chỉ lỗi không tìm thấy trang.'
}
