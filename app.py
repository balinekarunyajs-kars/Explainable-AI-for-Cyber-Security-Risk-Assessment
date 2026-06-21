import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import joblib
import shap

model =joblib.load('models/rf_model.pkl')
feature_names=joblib.load('models/feature_names.pkl')
le_proto=joblib.load('models/le_proto.pkl')
le_service=joblib.load('models/le_service.pkl')
le_state=joblib.load('models/le_state.pkl')

explainer = shap.TreeExplainer(model)

st.title("Explainable AI for Cyber Security Risk Assesment")

st.header("Network Traffic Details")

proto = st.selectbox("Protocol",le_proto.classes_)

service = st.selectbox("Service",le_service.classes_)

state = st.selectbox("State",le_state.classes_)

dur = st.number_input("Duration",0.0)

spkts = st.number_input("Source Packets",0)

dpkts = st.number_input("Destination Packets",0)

sbytes = st.number_input("Source Bytes",0)

dbytes = st.number_input("Destination Bytes",0)

rate = st.number_input("Rate",0.0)

sload = st.number_input("Source Load",0.0)

dload = st.number_input("Destination Load",0.0)

sloss = st.number_input("Source Loss",0)

dloss = st.number_input("Destination Loss",0)

sinpkt = st.number_input("Source Inter Packet Time",0.0)

dinpkt = st.number_input("Destination Inter Packet Time",0.0)

sjit = st.number_input("Source Jitter",0.0)

djit = st.number_input("Destination Jitter",0.0)

swin = st.number_input("Source Window",0)

stcpb = st.number_input("Source TCP Base",0)

dtcpb = st.number_input("Destination TCP Base",0)

dwin = st.number_input("Destination Window",0)

tcprtt = st.number_input("TCP RTT",0.0)

synack = st.number_input("SYN ACK",0.0)

ackdat = st.number_input("ACK DAT",0.0)

smean = st.number_input("Source Mean",0.0)

dmean = st.number_input("Destination Mean",0.0)

trans_depth = st.number_input("Transaction Depth",0)

response_body_len = st.number_input(
    "Response Body Length",
    0
)

ct_src_dport_ltm = st.number_input(
    "CT SRC DPORT LTM",
    0
)

ct_dst_sport_ltm = st.number_input(
    "CT DST SPORT LTM",
    0
)

is_ftp_login = st.number_input(
    "FTP Login",
    0
)

ct_ftp_cmd = st.number_input(
    "FTP Commands",
    0
)

ct_flw_http_mthd = st.number_input(
    "HTTP Methods",
    0
)

is_sm_ips_ports = st.number_input(
    "Same IP Ports",
    0
)

if st.button("Predict"):

    input_data = pd.DataFrame({
        'proto': [le_proto.transform([proto])[0]],
        'service':[le_service.transform([service])[0]],
        'state':[le_state.transform([state])[0]],
        'dur':[dur],
        'spkts':[spkts],
        'dpkts':[dpkts],
        'sbytes':[sbytes],
        'dbytes':[dbytes],
        'rate':[rate],
        'sload':[sload],
        'dload':[dload],
        'sloss':[sloss],
        'dloss':[dloss],
        'sinpkt':[sinpkt],
        'dinpkt':[dinpkt],
        'sjit':[sjit],
        'djit':[djit],
        'swin':[swin],
        'stcpb':[stcpb],
        'dtcpb':[dtcpb],
        'dwin':[dwin],
        'tcprtt':[tcprtt],
        'synack':[synack],
        'ackdat':[ackdat],
        'smean':[smean],
        'dmean':[dmean],
        'trans_depth':[trans_depth],
        'response_body_len':[response_body_len],
        'ct_src_dport_ltm':[ct_src_dport_ltm],
        'ct_dst_sport_ltm':[ct_dst_sport_ltm],
        'is_ftp_login':[is_ftp_login],
        'ct_ftp_cmd':[ct_ftp_cmd],
        'ct_flw_http_mthd':[ct_flw_http_mthd],
        'is_sm_ips_ports':[is_sm_ips_ports]

    })
    input_data = input_data[feature_names]

    pred = model.predict(input_data)[0]
    prob = model.predict_proba(input_data)[0][1]
    st.subheader("Prediction")
    
    if pred == 1:
        st.error("Malicious Traffic Detected")
    else:
        st.success("Benign Traffic Detected")

    st.write(f"Prediction Probability : {prob:.2f}")

    st.subheader("Risk Assessment")

    if prob < 0.3:
        st.info("Low Risk")
    elif prob < 0.7:
        st.warning("Moderate Risk")
    else:
        st.error("High Risk")


    shap_value=explainer.shap_values(input_data)
    shap_single=shap_value[0,:,1]

    explanation=pd.DataFrame({
    'Feature':input_data.columns,
    'SHAP Value':shap_single,
    'Value':input_data.iloc[0]
})

    explanation['Abs SHAP Value']=explanation['SHAP Value'].abs()
    top_features=explanation.sort_values(by='Abs SHAP Value',ascending=False).head(5)

    st.subheader("Top 5 Contributing Features")
    for _, row in top_features.iterrows():
       if row['SHAP Value'] > 0:
        st.write(f"{row['Feature']} (Value: {row['Value']}) contributes to Malicious Prediction")
       else:
        st.write(f"{row['Feature']} (Value: {row['Value']}) contributes to Benign Prediction")

    st.subheader("Feature Contribution")
    st.dataframe(top_features[['Feature','Value','SHAP Value']])

    shap_exp=shap.Explanation(values=shap_single,base_values=explainer.expected_value[1], feature_names=feature_names, data=input_data.iloc[0])

    st.header("SHAP Waterfall Plot")

    fig=plt.figure(figsize=(10,6))
    shap.plots.waterfall(shap_exp,show=False)
    st.pyplot(fig)