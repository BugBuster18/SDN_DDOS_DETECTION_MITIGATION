from ddos_ml.sdn_runtime import aggregate_bidirectional_rows


def make_row(dpid, src, sport, dst, dport, packets, bytes_, duration=10.0, proto=6):
    sec = int(duration)
    nsec = int((duration - sec) * 1_000_000_000)
    return {
        "datapath_id": dpid,
        "ip_src": src,
        "tp_src": sport,
        "ip_dst": dst,
        "tp_dst": dport,
        "ip_proto": proto,
        "packet_count": packets,
        "byte_count": bytes_,
        "duration_sec": sec,
        "duration_nsec": nsec,
        "match_fields": {"eth_type": 2048, "ipv4_src": src, "ipv4_dst": dst, "ip_proto": proto},
    }


def test_combines_forward_and_reverse_counters():
    rows = [
        make_row(1, "10.0.0.1", 12345, "10.0.0.2", 80, 500, 40000, 10.0),
        make_row(1, "10.0.0.2", 80, "10.0.0.1", 12345, 300, 20000, 9.0),
    ]
    result = aggregate_bidirectional_rows(rows)
    assert len(result) == 1
    assert result[0]["packet_count"] == 800
    assert result[0]["byte_count"] == 60000
    assert result[0]["duration_sec"] == 10
    assert result[0]["duration_nsec"] == 0
    assert len(result[0]["direction_rows"]) == 2


def test_deduplicates_conversation_seen_at_multiple_switches():
    rows = [
        make_row(1, "10.0.0.1", 12345, "10.0.0.2", 80, 500, 40000),
        make_row(1, "10.0.0.2", 80, "10.0.0.1", 12345, 300, 20000),
        make_row(2, "10.0.0.1", 12345, "10.0.0.2", 80, 500, 40000),
        make_row(2, "10.0.0.2", 80, "10.0.0.1", 12345, 300, 20000),
    ]
    result = aggregate_bidirectional_rows(rows)
    assert len(result) == 1
    assert result[0]["packet_count"] == 800
    assert result[0]["byte_count"] == 60000


def test_keeps_distinct_conversations_separate():
    rows = [
        make_row(1, "10.0.0.1", 12345, "10.0.0.2", 80, 10, 1000),
        make_row(1, "10.0.0.3", 12346, "10.0.0.4", 80, 20, 2000),
    ]
    result = aggregate_bidirectional_rows(rows)
    assert len(result) == 2


def test_ignores_non_ipv4_or_missing_endpoint_rows():
    rows = [{"datapath_id": 1, "packet_count": 10, "byte_count": 100}]
    assert aggregate_bidirectional_rows(rows) == []


def test_protocol_is_part_of_conversation_key():
    rows = [
        make_row(1, "10.0.0.1", 0, "10.0.0.2", 0, 10, 1000, proto=1),
        make_row(1, "10.0.0.1", 0, "10.0.0.2", 0, 20, 2000, proto=17),
    ]
    assert len(aggregate_bidirectional_rows(rows)) == 2


def test_aggregated_live_features_match_bidirectional_totals():
    from ddos_ml.runtime import live_feature_frame

    rows = [
        make_row(1, "10.0.0.1", 12345, "10.0.0.2", 80, 500, 40000, 10.0),
        make_row(1, "10.0.0.2", 80, "10.0.0.1", 12345, 300, 20000, 9.0),
    ]
    conversations = aggregate_bidirectional_rows(rows)
    features = live_feature_frame(conversations)

    assert features.loc[0, "packet_count"] == 800
    assert features.loc[0, "byte_count"] == 60000
    assert abs(features.loc[0, "packet_rate"] - 80.0) < 1e-9
    assert abs(features.loc[0, "byte_rate"] - 6000.0) < 1e-9
    assert abs(features.loc[0, "avg_packet_size"] - 75.0) < 1e-9
