# -*- coding: utf-8 -*-
"""XCS 云交易服务 (实验性)

来源: 客户端 CEF 页 JS (window.API.PromiseQuery*) 与内存实测
服务: https://xcsservice.hexin.cn:8001

已知请求契约 (JS 侧):
    standard = {reqtype, userkey, refresh, cachedata, setcode}
    extra    = {zjzh, ...}
    userkey  = f"{qsid}_{zjzh}_{seq}"  (例: 31_12345678_1542)

reqtype 对照:
    1537 当日持仓  1538 当日成交  1544 资金明细
    2304 申购额度  2314 中签/配号  2318 通用查询(带 extra_cmd)

注意: 直连可能需要登录后的 cookie; 本模块用于交互式验证。
"""
import requests

XCS_HOST = "https://xcsservice.hexin.cn:8001"

PATHS = {
    "batch_query_status": "/capitalinfo/quick/v1/batch_query_status",
    "hold_stock": "/capitalinfo/pc_support/v1/hold_stock",
    "chicangjcmx": "/capitalinfo/info/chicangjcmx",
    "qingcanggpmx": "/capitalinfo/info/qingcanggpmx",
    "profit_analysis": "/capitalinfo/pc_support/v1/profit_analysis",
    "daily_detail_profit_loss": "/capitalinfo/pc_support/v1/daily_detail_profit_loss",
    "interval_profit": "/capitalinfo/pc_support/v1/interval_profit",
    "close_stock": "/capitalinfo/pc_support/v1/close_stock",
    "trade_analysis": "/capitalinfo/account/trade/v1/analysis",
    "account_analysis": "/capitalinfo/accountAnalysis/getAnalysis",
}

REQTYPE = {
    1537: "当日持仓",
    1538: "当日成交",
    1544: "资金明细",
    2304: "申购额度",
    2314: "中签/配号查询",
    2318: "通用查询",
}


class XcsClient:
    def __init__(self, session=None, timeout: int = 20):
        self.http = session or requests.Session()
        self.timeout = timeout

    def request(self, path: str, params: dict = None, method: str = "POST",
                data: dict = None, headers: dict = None):
        url = path if path.startswith("http") else XCS_HOST + path
        kwargs = {"timeout": self.timeout}
        if params:
            kwargs["params"] = params
        if data:
            kwargs["data"] = data
        if headers:
            kwargs["headers"] = headers
        r = self.http.request(method, url, **kwargs)
        return r

    def query_raw(self, reqtype: int, userkey: str, zjzh: str, **extra):
        params = {
            "reqtype": str(reqtype),
            "userkey": userkey,
            "refresh": "1",
            "cachedata": "1",
            "setcode": "",
            "html_callback": "xcs_fnNotify",
            "jsonway": "1",
            "zjzh": zjzh,
        }
        params.update(extra)
        return self.request(PATHS["batch_query_status"], params=params, method="GET")
