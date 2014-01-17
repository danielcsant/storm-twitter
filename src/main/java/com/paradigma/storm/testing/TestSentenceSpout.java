package com.paradigma.storm.testing;

import backtype.storm.Config;
import backtype.storm.spout.SpoutOutputCollector;
import backtype.storm.task.TopologyContext;
import backtype.storm.topology.OutputFieldsDeclarer;
import backtype.storm.topology.base.BaseRichSpout;
import backtype.storm.tuple.Fields;
import backtype.storm.tuple.Values;
import backtype.storm.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Created with IntelliJ IDEA.
 * User: dcarroza
 * Date: 15/01/14
 * Time: 11:32
 * To change this template use File | Settings | File Templates.
 */
public class TestSentenceSpout extends BaseRichSpout{

    public static Logger LOG = LoggerFactory.getLogger(TestSentenceSpout.class);
    boolean _isDistributed;
    SpoutOutputCollector _collector;

    public TestSentenceSpout() {
        this(true);
    }

    public TestSentenceSpout(boolean isDistributed) {
        _isDistributed = isDistributed;
    }

    public void open(Map conf, TopologyContext context, SpoutOutputCollector collector) {
        _collector = collector;
    }

    public void close() {

    }

    public void nextTuple() {
        Utils.sleep(100);
        final String[] words = new String[] {
                "Do you see any Teletubbies in here?",
                "Do you see a slender plastic tag clipped to my shirt with my name printed on it?",
                "Do you see a little Asian child with a blank expression on his face sitting outside on a mechanical helicopter that shakes when you put quarters in it?",
                "No?",
                "Well, that's what you see at a toy store"};
        final Random rand = new Random();
        final String word = words[rand.nextInt(words.length)];
        _collector.emit(new Values(word));
    }

    public void ack(Object msgId) {

    }

    public void fail(Object msgId) {

    }

    public void declareOutputFields(OutputFieldsDeclarer declarer) {
        declarer.declare(new Fields("word"));
    }

    @Override
    public Map<String, Object> getComponentConfiguration() {
        if(!_isDistributed) {
            Map<String, Object> ret = new HashMap<String, Object>();
            ret.put(Config.TOPOLOGY_MAX_TASK_PARALLELISM, 1);
            return ret;
        } else {
            return null;
        }
    }

}
